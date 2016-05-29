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
#include <string.h>
#include <unistd.h>

#include "lc.h"

#define BPF_BUF_LEN 4096
#define DLT_BUF_LEN 64

static int set_ether_filter(struct lc_dev *);
static int set_ieee80211_filter(struct lc_dev *);

/*
 * Initializes a packet device context with the given interface, channel,
 * source address and destionation address.
 * Returns 0 on success, -1 otherwise.
 */
int
lc_open(struct lc_dev *dev, const char *iface, int chan,
    const char *from_addr, const char *to_addr)
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

	if (from_addr != NULL) {
		if (lc_addr_parse(dev->from_addr, from_addr) == -1) {
			warnx("invalid source address: %s", from_addr);
			return -1;
		}

		dev->r = 1;
	}

	if (to_addr != NULL) {
		if (lc_addr_parse(dev->to_addr, to_addr) == -1) {
			warnx("invalid destination address: %s", to_addr);
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

	/* Find a suitable network interface. */
	struct ifreq ifr;
	if (iface != NULL) {
		strlcpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));
	} else {
		struct ifaddrs *ifaddr;
		if (getifaddrs(&ifaddr) == -1) {
			warn("failed to retrieve interface addresses");
			return -1;
		}

		for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
			if ((ifa->ifa_flags & IFF_UP) == 0)
				continue;
			if (ifa->ifa_flags & IFF_LOOPBACK)
				continue;
			iface = ifa->ifa_name;
		}

		if (iface == NULL) {
			warnx("no suitable network interface found");
			freeifaddrs(ifaddr);
			return -1;
		}

		strlcpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));
		freeifaddrs(ifaddr);
	}

	if (ioctl(dev->fd, BIOCSETIF, &ifr) == -1) {
		warn("failed to set BPF device interface");
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
		warn("failed to retrieve available datalink types");
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
		warnx("no suitable datalink type found");
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

	/* Retrieve the local interface address. */
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
		if (sdl->sdl_alen != sizeof(dev->this_addr))
			continue;

		memcpy(dev->this_addr, LLADDR(sdl), sizeof(dev->this_addr));
		if_finished = 1;
		break;
	}

	if (!if_finished) {
		warnx("failed to find address for interface");
		goto err;
	}

	/* Set the proper filter code depending on the device's datalink type. */
	int rc;
	switch (dev->dlt) {
	case LC_DLT_EN10MB:
		rc = set_ether_filter(dev);
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

//static void payload_dump(struct lc_payload *p)
//{
//	warnx("{ .tag = %08x, .chan = %d, .size = %d }", p->tag, p->chan, p->size);
//}

/*
 * Reads at most LC_DATA_SIZE bytes from a linkcat device.
 * Returns the number of bytes read (excluding packet data) on success,
 * 0 otherwise.
 */
ssize_t
lc_read(struct lc_dev *dev, void *buf, size_t len)
{
	uint8_t	pkt[BPF_BUF_LEN];
	ssize_t	nread;

	do {
		nread = read(dev->fd, pkt, sizeof(pkt));
		if (nread == -1 && errno == EINTR)
			continue;
	} while (nread == 0);

	if (nread == -1) {
		warn("failed to read packet data");
		return -1;
	}

	struct bpf_hdr *bpf_hdr = (struct bpf_hdr *)pkt;
	size_t bpf_hdrlen = bpf_hdr->bh_hdrlen;

	/* This should never happen. Check anyway. */
	if ((size_t)nread < bpf_hdrlen) {
		warnx("packet length under BPF header length");
		return -1;
	}

	nread -= bpf_hdrlen;

	size_t payload_off;
	switch (dev->dlt) {
	case LC_DLT_EN10MB:
		payload_off = offsetof(struct lc_ether_frame, payload);
		break;
	case LC_DLT_IEEE802_11:
		payload_off = offsetof(struct lc_ieee80211_frame, payload);
		break;
	default:
		return -1;
	}

	if ((size_t)nread < payload_off) {
		warnx("no payload in packet");
		return -1;
	}

	nread -= payload_off;

	if ((size_t)nread < LC_PAYLOAD_MIN) {
		warnx("payload size less than allowed");
		return -1;
	}

	struct lc_payload *payload =
	    (struct lc_payload *)(pkt + bpf_hdrlen + payload_off);

	payload->tag = ntohl(payload->tag);
	payload->chan = ntohs(payload->chan);
	payload->size = ntohs(payload->size);

	if (LC_PAYLOAD_MIN + payload->size != (size_t)nread) {
		warnx("payload size mismatch ");
		return -1;
	}

	size_t ncopy = len < payload->size ? len : payload->size;
	memcpy(buf, payload->data, ncopy);

	return ncopy;
}

/*
 * Writes at most LC_DATA_SIZE through a linkcat device.
 * Returns the number of bytes written (including packet data)
 * on success, 0 otherwise.
 * TODO: exclude packet data length in return value
 */
ssize_t
lc_write(struct lc_dev *dev, const void *buf, size_t len)
{
	if (LC_DATA_SIZE < len) {
		warnx("data size too large for writing");
		return -1;
	}

	size_t	 frame_len;
	void	*frame;
	struct	 lc_payload *payload;
	struct	 lc_ether_frame ether;
	struct	 lc_ieee80211_frame ieee80211;

	switch (dev->dlt) {
	case LC_DLT_EN10MB:
		frame_len = LC_ETHER_FRAME_MIN + len;
		frame = &ether;
		payload = &ether.payload;

		memcpy(ether.hdr.dst, dev->to_addr, sizeof(ether.hdr.dst));
		memcpy(ether.hdr.src, dev->this_addr, sizeof(ether.hdr.src));
		ether.hdr.type = htons(LC_ETHERTYPE);

		break;

	case LC_DLT_IEEE802_11:
		frame_len = LC_IEEE80211_FRAME_MIN + len;
		frame = &ieee80211;
		payload = &ieee80211.payload;

		ieee80211.hdr.fc[0] = LC_IEEE80211_FC0_TYPE;
		ieee80211.hdr.fc[1] = 0;
		memset(ieee80211.hdr.dur, 0, sizeof(ieee80211.hdr.dur));
		memcpy(ieee80211.hdr.dst, dev->to_addr, sizeof(ieee80211.hdr.dst));
		memcpy(ieee80211.hdr.src, dev->this_addr, sizeof(ieee80211.hdr.src));
		memcpy(ieee80211.hdr.bssid, dev->this_addr, sizeof(ieee80211.hdr.bssid));
		memset(ieee80211.hdr.seq, 0, sizeof(ieee80211.hdr.seq));

		ieee80211.llc.dsap = 0;
		ieee80211.llc.ssap = 0;
		ieee80211.llc.ctl = 0;
		memset(ieee80211.llc.oui, 0, sizeof(ieee80211.llc.oui));
		ieee80211.llc.type = htons(LC_ETHERTYPE);

		break;

	default:
		warnx("invalid datalink type");
		return -1;
	}

	payload->tag = htonl(LC_TAG);
	payload->chan = htons(dev->chan);
	payload->size = htons(len);
	memcpy(payload->data, buf, len);

	ssize_t nw;
	do {
		nw = write(dev->fd, frame, frame_len);
		if (nw == -1 || (errno == EINTR || errno == ENOBUFS))
			continue;
		else
			break;
	} while (1);

	if (nw == -1)
		warn("failed to write packet data");

	return nw;
}

void
lc_close(struct lc_dev *dev)
{
	close(dev->fd);
}

static int
set_ether_filter(struct lc_dev *dev)
{
	struct bpf_insn code_default[LC_ETHER_FILTER_LEN]
	    = LC_ETHER_FILTER(dev->from_addr, dev->chan);

	struct bpf_insn code_no_src[LC_ETHER_FILTER_NO_SRC_LEN]
	    = LC_ETHER_FILTER_NO_SRC(dev->chan);

	struct bpf_program prog_default = {
	    .bf_len = LC_ETHER_FILTER_LEN,
	    .bf_insns = code_default
	};

	struct bpf_program prog_no_src = {
	    .bf_len = LC_ETHER_FILTER_NO_SRC_LEN,
	    .bf_insns = code_no_src
	};

	struct bpf_program *prog = lc_addr_is_broadcast(dev->from_addr)
	    ? &prog_no_src
	    : &prog_default;

	return ioctl(dev->fd, BIOCSETF, prog);
}

static int
set_ieee80211_filter(struct lc_dev *dev)
{
	struct bpf_insn code[LC_IEEE80211_FILTER_LEN] =
	    LC_IEEE80211_FILTER(dev->from_addr, dev->chan);

	struct bpf_program prog = {
	    .bf_insns = code,
	    .bf_len = LC_IEEE80211_FILTER_LEN
	};

	return ioctl(dev->fd, BIOCSETF, &prog);
}
