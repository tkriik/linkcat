#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/endian.h>
#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <ifaddrs.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lc.h"
#include "log.h"
#include "proto.h"

static int dev_fill_addr(struct dev *, const char *);

/* BPF device paths. */
#define BPF_DEV_PATH_CNT 8
static const char *bpf_dev_paths[BPF_DEV_PATH_CNT] = {
    "/dev/bpf0", "/dev/bpf1", "/dev/bpf2", "/dev/bpf3",
    "/dev/bpf4", "/dev/bpf5", "/dev/bpf6", "/dev/bpf7"
};

/* BPF filter code for reading server-bound BeaconFS frames. */
static struct bpf_insn bpf_server_code[] = {
    BPF_STMT(BPF_LD  + BPF_B   + BPF_ABS, 0),
    BPF_STMT(BPF_ALU + BPF_AND + BPF_K,   BEACONFS_FC0_MASK),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   BEACONFS_FC0_SERVER_BOUND, 0, 3),
    BPF_STMT(BPF_LD  + BPF_W   + BPF_ABS, BEACONFS_TAG_OFFSET),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   BEACONFS_TAG, 0, 1),
    BPF_STMT(BPF_RET + BPF_K,             BEACONFS_FRAME_SIZE),
    BPF_STMT(BPF_RET + BPF_K,             0)
};

static struct bpf_program bpf_server_prog = {
    sizeof(bpf_server_code) / sizeof(bpf_server_code[0]),
    bpf_server_code
};

/* BPF filter code for reading client-bound BeaconFS frames. */
static struct bpf_insn bpf_client_code[] = {
    BPF_STMT(BPF_LD  + BPF_B   + BPF_ABS, 0),
    BPF_STMT(BPF_ALU + BPF_AND + BPF_K,   BEACONFS_FC0_MASK),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   BEACONFS_FC0_CLIENT_BOUND, 0, 3),
    BPF_STMT(BPF_LD  + BPF_W   + BPF_ABS, BEACONFS_TAG_OFFSET),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   BEACONFS_TAG, 0, 1),
    BPF_STMT(BPF_RET + BPF_K,             BEACONFS_FRAME_SIZE),
    BPF_STMT(BPF_RET + BPF_K,             0)
};

static struct bpf_program bpf_client_prog = {
    sizeof(bpf_client_code) / sizeof(bpf_client_code[0]),
    bpf_client_code
};

/*
 * Opens a BSD-specific link device context.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
dev_open(struct dev *dev, const char *interface, enum dev_type type)
{
	int	rc;
	size_t	i;
	u_int	buf_len;
	struct	ifreq ifr;
	u_int	dlt;
	u_int	imm;
	struct	bpf_program *prog_ptr;

	dev->type = type;

	log_debug("reading interface address");
	rc = dev_fill_addr(dev, interface);
	if (rc == -1)
		goto err_open;

	log_debug("opening BPF device");
	for (i = 0; i < BPF_DEV_PATH_CNT; i++) {
		dev->fd = open(bpf_dev_paths[i], O_RDWR);
		if (dev->fd != -1)
			break;
		else if (i == BPF_DEV_PATH_CNT - 1)
			goto err_open;
	}

	log_debug("setting BPF device buffer length to %d", DEV_BUF_LEN);
	buf_len = DEV_BUF_LEN;
	rc = ioctl(dev->fd, BIOCSBLEN, &buf_len);
	if (rc == -1)
		goto err_ioctl;

	log_debug("setting BPF device interface to %s", interface);
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));
	rc = ioctl(dev->fd, BIOCSETIF, &ifr);
	if (rc == -1)
		goto err_ioctl;

	log_debug("setting BPF device data link type to %d", DLT_IEEE802_11);
	dlt = DLT_IEEE802_11;
	rc = ioctl(dev->fd, BIOCSDLT, &dlt);
	if (rc == -1)
		goto err_ioctl;

	log_debug("enabling immediate reads on BPF device");
	imm = 1;
	rc = ioctl(dev->fd, BIOCIMMEDIATE, &imm);
	if (rc == -1)
		goto err_ioctl;

	log_debug("setting BPF device filter program");
	switch (dev->type) {
	case DEV_SERVER:
		prog_ptr = &bpf_server_prog;
		break;
	case DEV_CLIENT:
		prog_ptr = &bpf_client_prog;
		break;
	default:
		goto err_ioctl;
	};

	rc = ioctl(dev->fd, BIOCSETF, prog_ptr);
	if (rc == -1)
		goto err_ioctl;

	log_debug("locking BPF device");
	rc = ioctl(dev->fd, BIOCLOCK);
	if (rc == -1)
		goto err_ioctl;

	return 0;

err_ioctl:
	close(dev->fd);
err_open:
	return -1;
}

/*
 * Reads a single BeaconFS message from a BeaconFS device.
 * The call blocks until a message is received.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
dev_read_msg(struct dev *dev, struct beaconfs_msg *msg)
{
	uint8_t	pkt[DEV_BUF_LEN];
	ssize_t	nread;
	struct	bpf_hdr *bpf_hdr;
	size_t	bpf_hdrlen;
	struct	beaconfs_frame *frame;
	size_t	msg_type_size;

	do {
		nread = read(dev->fd, pkt, sizeof(pkt));
		if (nread == -1 && errno == EINTR)
			continue;
	} while (nread == 0);

	if (nread == -1)
		return -1;

	bpf_hdr = (struct bpf_hdr *)pkt;
	bpf_hdrlen = bpf_hdr->bh_hdrlen;

	/* This should never happen. Check anyway. */
	if ((size_t)nread < bpf_hdrlen)
		return -1;

	nread -= bpf_hdrlen;
	if ((size_t)nread < BEACONFS_MIN_FRAME_SIZE)
		return -1;

	frame = (struct beaconfs_frame *)(pkt + bpf_hdrlen);
	msg_type_size = beaconfs_msg_type_size(frame->val.type);

	nread -= BEACONFS_MIN_FRAME_SIZE;
	if ((size_t)nread < msg_type_size)
		return -1;

	memcpy(msg->src, frame->src, sizeof(msg->src));
	memcpy(msg->dst, frame->dst, sizeof(msg->dst));
	msg->val = frame->val;

	return 0;
}

/*
 * Writes a BeaconFS message through a BeaconFS device.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
dev_write_msg(struct dev *dev, struct beaconfs_msg *msg)
{
	struct	beaconfs_frame frame;
	uint8_t	fc0;
	ssize_t	nwritten;

	switch (dev->type) {
	case DEV_SERVER:
		fc0 = BEACONFS_FC0_CLIENT_BOUND;
		break;
	case DEV_CLIENT:
		fc0 = BEACONFS_FC0_SERVER_BOUND;
		break;
	default:
		return -1;
	}

	memset(&frame, 0, sizeof(frame));

	frame.fc[0] = fc0;
	memcpy(frame.dst, msg->dst, sizeof(frame.dst));
	memcpy(frame.src, dev->addr, sizeof(frame.src));
	memcpy(frame.bssid, dev->addr, sizeof(frame.bssid));
	frame.tag = htobe32(BEACONFS_TAG);
	frame.val = msg->val;

	do {
		nwritten = write(dev->fd, &frame, sizeof(frame));
		if (nwritten == -1) {
			switch (errno) {
			case EINTR:
				continue;
			default:
				return -1;
			}
		}
	} while (0);

	return 0;
}

/*
 * Closes a BPF device.
 */
void
dev_close(struct dev *dev)
{
	close(dev->fd);
}

/*
 * Sets the BeaconFS address of a device context to the link-level
 * address of the given interface.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
dev_fill_addr(struct dev *dev, const char *interface)
{
	int	rc;
	int	finished = 0;
	struct	ifaddrs *ifaddr, *ifa;
	struct	sockaddr_dl *sdl;

	rc = getifaddrs(&ifaddr);
	if (rc == -1)
		return -1;

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_name == NULL || strcmp(interface, ifa->ifa_name) != 0)
			continue;

		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_LINK)
			continue;

		sdl = (struct sockaddr_dl *)ifa->ifa_addr;
		if (sdl->sdl_alen != sizeof(dev->addr))
			continue;

		memcpy(dev->addr, LLADDR(sdl), sizeof(dev->addr));
		finished = 1;
		break;
	}

	freeifaddrs(ifaddr);

	return finished ? 0 : -1;
}
