#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>

#include <err.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <string.h>
#include <unistd.h>

#include "lc.h"
#include "log.h"

#define BPF_BUF_LEN 4096
#define DLT_BUF_LEN 64

static int set_ether_filter(struct lc_dev *);
static int set_ieee80211_filter(struct lc_dev *);

int
lc_open(struct lc_dev *dev, const char *ifname, uint16_t chan, struct lc_addr dst)
{
	int rc;

	dev->chan = chan;

	log_debug("opening BPF device");
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

	for (const char **path = bpf_dev_paths; *path != NULL; path++) {
		dev->fd = open(*path, O_RDWR);
		if (dev->fd != -1)
			break;
	}

	if (dev->fd == -1)
		return -1;

	log_debug("setting BPF device buffer length to %d", BPF_BUF_LEN);
	u_int buf_len = BPF_BUF_LEN;
	if (ioctl(dev->fd, BIOCSBLEN, &buf_len) == -1)
		goto err;

	log_debug("setting BPF device interface to %s", ifname);
	struct ifreq ifr;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(dev->fd, BIOCSETIF, &ifr) == -1)
		goto err;

	log_debug("reading available data-link types");
	u_int dlt_buf[DLT_BUF_LEN];
	struct bpf_dltlist dlt_list = {
	    .bfl_len = DLT_BUF_LEN,
	    .bfl_list = dlt_buf
	};

	if (ioctl(dev->fd, BIOCGDLTLIST, &dlt_list) == -1)
		goto err;

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

	if (dlt == 0)
		goto err;

	log_debug("setting BPF device data-link type to %d", dlt);
	if (ioctl(dev->fd, BIOCSDLT, &dlt) == -1)
		goto err;

	dev->dlt = dlt;

	log_debug("enabling immediate reads on BPF device");
	u_int imm = 1;
	if (ioctl(dev->fd, BIOCIMMEDIATE, &imm) == -1)
		goto err;

	log_debug("reading interface address");
	struct ifaddrs *ifaddr;
	if (getifaddrs(&ifaddr) == -1)
		return -1;

	int if_finished = 0;
	for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_name == NULL || strcmp(ifname, ifa->ifa_name) != 0)
			continue;

		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_LINK)
			continue;

		struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
		if (sdl->sdl_alen != sizeof(dev->src))
			continue;

		memcpy(dev->src, LLADDR(sdl), sizeof(dev->src));
		if_finished = 1;
		break;
	}

	if (!if_finished)
		goto err;

	log_debug("setting BPF device filter");
	switch (dev->dlt) {
	case LC_DLT_EN10MB:
		rc = set_ether_filter(dev->fd, dev->chan, dst);
		rc = set_ether_filter(dev);
		break;
	case LC_DLT_IEEE802_11:
		rc = set_ieee80211_filter(dev);
		break;
	default:
		goto err;
	}

	if (rc == -1)
		goto err;

	log_debug("locking BPF device");
	if (ioctl(dev->fd, BIOCLOCK) == -1)
		goto err;

	return 0;

err:
	close(dev->fd);

	return -1;
}

void
lc_close(struct lc_dev *dev)
{
	close(dev->fd);
}

static int
set_ether_filter(int fd, uint16_t chan, struct lc_addr src)
{
	struct bpf_insn code[LC_ETHER_FILTER_LEN] =
	    LC_ETHER_FILTER(src.data, chan);

	struct bpf_program prog = {
	    .bf_len = LC_ETHER_FILTER_LEN,
	    .bf_insns = code
	};

	return ioctl(fd, BIOCSETF, &prog);
}

static int
set_ieee80211_filter(int fd, uint16_t chan, struct lc_addr src)
{
	struct bpf_insn code[LC_IEEE80211_FILTER_LEN] =
	    LC_IEEE80211_FILTER(src.data, chan);

	struct bpf_program prog = {
	    .bf_len = LC_IEEE80211_FILTER_LEN,
	    .bf_insns = code
	};

	return ioctl(fd, BIOCSETF, &prog);
}
