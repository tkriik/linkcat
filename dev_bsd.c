#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "lc.h"

#define BPF_BUF_LEN 4096
#define DLT_BUF_LEN 64

static int set_ether_filter(struct lc_dev *, int);
static int set_ieee80211_filter(struct lc_dev *);

int
lc_open(struct lc_dev *dev, const char *iface, int chan,
    const char *src, const char *dst, int local)
{
	dev->chan = chan;

	/*
	 * Parse the source and destination addresses
	 * and set the device mode accordingly.
	 *  - no destination address -> read only
	 *  - no source address -> write only
	 *  - both addresses -> read and write
	 */
	dev->r = 0;
	dev->w = 0;

	if (src != NULL) {
		if (lc_addr_parse(dev->src, src) == -1) {
			warnx("invalid source address: %s", src);
			return -1;
		}

		dev->r = 1;
	}

	if (dst != NULL) {
		if (lc_addr_parse(dev->dst, dst) == -1) {
			warnx("invalid destination address: %s", dst);
			return -1;
		}

		dev->w = 1;
	}

	/* Open the first available BPF device file descriptor. */
	const char *bpf_dev_paths[] = {
	    "/dev/bpf",
	    "/dev/bpf0",
	    "/dev/bpf1",
	    "/dev/bpf2",
	    "/dev/bpf3",
	    "/dev/bpf4",
	    "/dev/bpf5",
	    "/dev/bpf6",
	    "/dev/bpf7",
	    "/dev/bpf8",
	    "/dev/bpf9",
	    NULL
	};

	int mode;
	if (dev->r && dev->w)
		mode = O_RDWR;
	else if (dev->r)
		mode = O_RDONLY;
	else if (dev->w)
		mode = O_WRONLY;
	else {
		warnx("no read nor write mode set");
		return -1;
	}

	for (const char **path_ptr = bpf_dev_paths; *path_ptr != NULL; path_ptr++) {
		dev->fd = open(*path_ptr, mode);
		if (dev->fd != -1)
			break;
	}

	if (dev->fd == -1) {
		warn("failed to open BPF device");
		return -1;
	}

	/* Set the read buffer length. The default one is larger than necessary. */
	u_int buf_len = BPF_BUF_LEN;
	if (ioctl(dev->fd, BIOCSBLEN, &buf_len) == -1) {
		warn("failed to set BPF device buffer length");
		goto err;
	}

	/* Set the BPF device interface. */
	struct ifreq ifr;
	strlcpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));
	if (ioctl(dev->fd, BIOCSETIF, &ifr) == -1) {
		warn("failed to set BPF device interface to %s", iface);
		goto err;
	}

	/*
	 * Retrieve the available datalink types for the interface
	 * and select one (if found) that is supported by linkcat.
	 */
	u_int dlt_buf[DLT_BUF_LEN];
	struct bpf_dltlist dlt_list = {
	    .bfl_len = DLT_BUF_LEN,
	    .bfl_list = dlt_buf
	};

	if (ioctl(dev->fd, BIOCGDLTLIST, &dlt_list) == -1) {
		warn("failed to read available datalink types for %s", iface);
		goto err;
	}

	u_int dlt = 0;
	for (u_int i = 0; i < dlt_list.bfl_len; i++) {
		switch (dlt_list.bfl_list[i]) {
		case DLT_EN10MB:
			dlt = LC_DLT_EN10MB;
			break;
		case DLT_IEEE802_11:
			dlt = LC_DLT_IEEE802_11;
			break;
		default:
			continue;
		}

		if (dlt != 0)
			break;
	}

	if (dlt == 0) {
		warnx("no suitable datalink type found for %s", iface);
		goto err;
	}

	if (ioctl(dev->fd, BIOCSDLT, &dlt) == -1) {
		warn("failed to set BPF device datalink type");
		goto err;
	}

	dev->dlt = dlt;

	/* Enable immediate reads for real-time data acknowledgement. */
	u_int imm = 1;
	if (ioctl(dev->fd, BIOCIMMEDIATE, &imm) == -1) {
		warn("failed to set immediate reads on BPF device");
		goto err;
	}

	/* Retrieve the local device address. */
	struct ifaddrs *ifaddr;
	if (getifaddrs(&ifaddr) == -1) {
		warn("failed to retrieve interface addresses");
		return -1;
	}

	int if_finished = 0;
	for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_name == NULL || strcmp(iface, ifa->ifa_name) != 0)
			continue;

		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_LINK)
			continue;

		struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
		if (sdl->sdl_alen != sizeof(dev->hw_addr))
			continue;

		memcpy(dev->hw_addr, LLADDR(sdl), sizeof(dev->hw_addr));
		if_finished = 1;
		break;
	}

	if (!if_finished) {
		warnx("failed to find hardware address of %s", iface);
		goto err;
	}

	/* Set the proper filter code depending on the device's datalink type. */
	int rc;
	switch (dev->dlt) {
	case LC_DLT_EN10MB:
		rc = set_ether_filter(dev, local);
		break;
	case LC_DLT_IEEE802_11:
		rc = set_ieee80211_filter(dev);
		break;
	default:
		warnx("invalid datalink type");
		goto err;
	}

	if (rc == -1) {
		warn("failed to set BPF device packet filter");
		goto err;
	}

	/* Finally lock the BPF device. */
	if (ioctl(dev->fd, BIOCLOCK) == -1) {
		warn("failed to lock BPF device");
		goto err;
	}

	return 0;

err:
	close(dev->fd);
	
	return -1;
}

ssize_t
lc_in(struct lc_dev *dev)
{
	uint8_t	pkt[BPF_BUF_LEN];
	ssize_t	nr;

	do {
		nr = read(dev->fd, pkt, sizeof(pkt));
		if (nr == -1 && errno == EINTR)
			continue;
	} while (nr == 0);

	if (nr == -1) {
		warn("failed to read packet data");
		return -1;
	}

	size_t lc_frame_hdr_size = 0;

	switch (dev->dlt) {
	case LC_DLT_EN10MB:
		lc_frame_hdr_size = sizeof(struct lc_ether_frame_hdr);
		break;
	case LC_DLT_IEEE802_11:
		lc_frame_hdr_size = sizeof(struct lc_ieee80211_frame_hdr);
		break;
	default:
		errx(1, "invalid datalink type");
	}

	struct bpf_hdr *bpf_hdr = (struct bpf_hdr *)pkt;
	size_t bpf_hdr_len = bpf_hdr->bh_hdrlen;
	size_t pkt_hdr_len = bpf_hdr_len + lc_frame_hdr_size;

	if ((size_t)nr < pkt_hdr_len) {
		warnx("incomplete header");
		return -1;
	}

	nr -= pkt_hdr_len;
	uint8_t *data = pkt + pkt_hdr_len;

	ssize_t nw;
	do
		nw = write(STDOUT_FILENO, data, nr);
	while (nw == -1 && errno == EINTR);

	if (nw == -1)
		err(1, "failed to write to stdout");

	return nw;
}

ssize_t
lc_out(struct lc_dev *dev)
{
	union {
		struct	lc_ether_frame_hdr ether;
		struct	lc_ieee80211_frame_hdr ieee80211;
		uint8_t	buf[LC_FRAME_BUF_SIZE];
	} frame_u;

	struct	 lc_ether_hdr *ether;
	struct	 lc_ieee80211_hdr *ieee80211;
	struct	 lc_ieee8022_llc_hdr *llc;
	struct	 lc_hdr *lc;
	void	*data;
	size_t	 frame_len;

	switch (dev->dlt) {
	case LC_DLT_EN10MB:
		ether = &frame_u.ether.hdr;
		lc = &frame_u.ether.lc;
		data = ((uint8_t *)&frame_u) + sizeof(frame_u.ether);
		frame_len = sizeof(frame_u.ether);

		memcpy(ether->dst, dev->dst, sizeof(ether->dst));
		memcpy(ether->src, dev->hw_addr, sizeof(ether->src));
		ether->type = htons(LC_ETHERTYPE);

		break;

	case LC_DLT_IEEE802_11:
		ieee80211 = &frame_u.ieee80211.hdr;
		llc = &frame_u.ieee80211.llc;
		lc = &frame_u.ieee80211.lc;
		data = ((uint8_t *)&frame_u) + sizeof(frame_u.ether);
		frame_len = sizeof(frame_u.ieee80211);

		ieee80211->fc[0] = LC_IEEE80211_FC0_TYPE;
		ieee80211->fc[1] = 0;
		memset(ieee80211->dur, 0, sizeof(ieee80211->dur));
		memcpy(ieee80211->dst, dev->dst, sizeof(ieee80211->dst));
		memcpy(ieee80211->src, dev->hw_addr, sizeof(ieee80211->src));
		memcpy(ieee80211->bssid, dev->hw_addr, sizeof(ieee80211->bssid));
		memset(ieee80211->seq, 0, sizeof(ieee80211->seq));

		llc->dsap = 0;
		llc->ssap = 0;
		llc->ctl = 0;
		memset(llc->oui, 0, sizeof(llc->oui));
		llc->type = htons(LC_ETHERTYPE);

		break;

	default:
		errx(1, "invalid datalink type");
		return -1;
	}

	lc->tag = htonl(LC_TAG);
	lc->chan = htons(dev->chan);

	ssize_t nr, nw;
	do
		nr = read(STDIN_FILENO, data, LC_DATA_SIZE);
	while (nr == -1 && errno == EINTR);

	if (nr == 0)
		return 0;

	if (nr == -1)
		err(1, "failed to read from stdin");

	frame_len += (size_t)nr;

	do
		nw = write(dev->fd, &frame_u, frame_len);
	while (nw == -1 && errno == EINTR);

	if (nw == -1) {
		warn("failed to write packet data");
		return -1;
	}

	return nw;
}

int
lc_stat(struct lc_dev *dev)
{
	struct bpf_stat st;

	if (ioctl(dev->fd, BIOCGSTATS, &st) == -1)
		return -1;

	dev->nrecv = st.bs_recv;
	dev->ndrop = st.bs_drop;

	return 0;
}

void
lc_close(struct lc_dev *dev)
{
	close(dev->fd);
	memset(dev, 0, sizeof(*dev));
}

static int
set_ether_filter(struct lc_dev *dev, int local)
{
	struct bpf_insn code_default[LC_ETHER_FILTER_LEN]
	    = LC_ETHER_FILTER(dev->src, dev->chan);

	struct bpf_insn code_no_local[LC_ETHER_FILTER_NO_LOCAL_LEN]
	    = LC_ETHER_FILTER_NO_LOCAL(dev->hw_addr, dev->chan);

	struct bpf_insn code_any[LC_ETHER_FILTER_ANY_LEN]
	    = LC_ETHER_FILTER_ANY(dev->chan);

	struct bpf_program prog_default = {
		.bf_len = LC_ETHER_FILTER_LEN,
		.bf_insns = code_default
	};

	struct bpf_program prog_no_local = {
		.bf_len = LC_ETHER_FILTER_NO_LOCAL_LEN,
		.bf_insns = code_no_local
	};

	struct bpf_program prog_any = {
		.bf_len = LC_ETHER_FILTER_ANY_LEN,
		.bf_insns = code_any
	};

	struct bpf_program *prog;
	if (lc_addr_is_broadcast(dev->src)) {
		if (local)
			prog = &prog_any;
		else
			prog = &prog_no_local;
	} else
		prog = &prog_default;

	return ioctl(dev->fd, BIOCSETF, prog);
}

static int
set_ieee80211_filter(struct lc_dev *dev)
{
	struct bpf_insn code[LC_IEEE80211_FILTER_LEN] =
	    LC_IEEE80211_FILTER(dev->src, dev->chan);

	struct bpf_program prog = {
	    .bf_insns = code,
	    .bf_len = LC_IEEE80211_FILTER_LEN
	};

	return ioctl(dev->fd, BIOCSETF, &prog);
}
