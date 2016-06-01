#ifndef _LC_H_
#define _LC_H_

#include <sys/socket.h>
#include <net/if.h>

#include <stddef.h>
#include <stdint.h>

#define LC_ADDR_LEN 6				/* linkcat address length. */

/*
 * Supported data-link level types.
 */
enum lc_dlt {
	LC_DLT_EN10MB		= 1,		/* Ethernet (10Mb) */
	LC_DLT_IEEE802_11	= 105		/* IEEE 802.11 wireless */
};

#define LC_ETHERTYPE		0x88B5		/* linkcat ethertype */
#define LC_ETHER_ADDR_LEN	LC_ADDR_LEN	/* Ethernet address length */

/*
 * Ethernet header.
 */
struct lc_ether_hdr {
	uint8_t		dst[LC_ETHER_ADDR_LEN];	/* destination address */
	uint8_t		src[LC_ETHER_ADDR_LEN];	/* source address */
	uint16_t	type;			/* ethertype */
} __packed;

/*
 * IEEE 802.2 logical link control header.
 */
struct lc_ieee8022_llc_hdr {
	uint8_t		dsap;			/* destination service access point */
	uint8_t		ssap;			/* source service access point */
	uint8_t		ctl;			/* control byte */
	uint8_t		oui[3];			/* organizationally unique id */
	uint16_t	type;			/* ethertype */
} __packed;

#define LC_IEEE80211_ADDR_LEN LC_ADDR_LEN	/* IEEE 802.11 address length */

/*
 * IEEE 802.11 header.
 */
struct lc_ieee80211_hdr {
	uint8_t	fc[2];				/* frame control */
	uint8_t dur[2];				/* duration control */
	uint8_t	dst[LC_IEEE80211_ADDR_LEN];	/* destination address */
	uint8_t src[LC_IEEE80211_ADDR_LEN];	/* source address */
	uint8_t bssid[LC_IEEE80211_ADDR_LEN];	/* BSSID */
	uint8_t seq[2];				/* sequence control */
} __packed;

#define LC_TAG		0x6d656f77		/* linkcat tag */
#define LC_CHAN_MAX	65535			/* maximum linkcat channel value */
#define LC_DATA_SIZE	1024			/* linkcat data block size */

/*
 * linkcat header.
 */
struct lc_hdr {
	uint32_t tag;				/* linkcat tag */
	uint16_t chan;				/* linkcat-specific virtual channel */
} __packed;

/*
 * linkcat Ethernet frame header.
 */
struct lc_ether_frame_hdr {
	struct lc_ether_hdr hdr;		/* Ethernet header */
	struct lc_hdr lc;			/* linkcat header */
} __packed;

#define LC_ETHER_FRAME_MAX (sizeof(struct lc_ether_frame_hdr) + LC_DATA_SIZE)

/*
 * linkcat IEEE 802.11 frame header.
 */
struct lc_ieee80211_frame_hdr {
	struct lc_ieee80211_hdr hdr;		/* IEEE 802.11 header */
	struct lc_ieee8022_llc_hdr llc;		/* LLC header */
	struct lc_hdr lc;			/* linkcat header */
} __packed;

#define LC_IEEE80211_FRAME_MAX (sizeof(struct lc_ieee80211_frame_hdr) + LC_DATA_SIZE)

#define LC_FRAME_BUF_SIZE 4096			/* linkcat frame buffer size */

/*
 * Utility macros for device address comparison in filter initializers.
 */
#define LC_ADDR_W(a) (((a)[2] << 24) | ((a)[3] << 16) | ((a)[4] << 8) | (a)[5])
#define LC_ADDR_H(a) (((a)[0] << 8)  |  (a)[1])

/*
 * Frame offset constants for Ethernet filter initializer.
 */
enum {
	LC_ETHER_FRAME_SRC_OFFSET	= offsetof(struct lc_ether_frame_hdr, hdr)
					+ offsetof(struct lc_ether_hdr, src),
	LC_ETHER_FRAME_TYPE_OFFSET	= offsetof(struct lc_ether_frame_hdr, hdr)
					+ offsetof(struct lc_ether_hdr, type),
	LC_ETHER_FRAME_TAG_OFFSET	= offsetof(struct lc_ether_frame_hdr, lc)
					+ offsetof(struct lc_hdr, tag),
	LC_ETHER_FRAME_CHAN_OFFSET	= offsetof(struct lc_ether_frame_hdr, lc)
					+ offsetof(struct lc_hdr, chan)
};

/*
 * Ethernet read filter initializer.
 */
#define LC_ETHER_FILTER(src, chan) {						\
	BPF_STMT(BPF_LD  + BPF_W   + BPF_ABS, LC_ETHER_FRAME_SRC_OFFSET + 2),	\
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_ADDR_W(src), 0, 9),		\
	BPF_STMT(BPF_LD  + BPF_H   + BPF_ABS, LC_ETHER_FRAME_SRC_OFFSET),	\
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_ADDR_H(src), 0, 7),		\
	BPF_STMT(BPF_LD  + BPF_H   + BPF_ABS, LC_ETHER_FRAME_TYPE_OFFSET),	\
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_ETHERTYPE, 0, 5),		\
	BPF_STMT(BPF_LD  + BPF_W   + BPF_ABS, LC_ETHER_FRAME_TAG_OFFSET),	\
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_TAG, 0, 3),			\
	BPF_STMT(BPF_LD  + BPF_H   + BPF_ABS, LC_ETHER_FRAME_CHAN_OFFSET),	\
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   (chan), 0, 1),			\
	BPF_STMT(BPF_RET + BPF_K,             LC_ETHER_FRAME_MAX),		\
	BPF_STMT(BPF_RET + BPF_K,             0)				\
}

#define LC_ETHER_FILTER_LEN 12

/*
 * Ethernet read filter initializer without source address rule.
 */
#define LC_ETHER_FILTER_NO_SRC(chan) {						\
	BPF_STMT(BPF_LD  + BPF_H   + BPF_ABS, LC_ETHER_FRAME_TYPE_OFFSET),	\
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_ETHERTYPE, 0, 5),		\
	BPF_STMT(BPF_LD  + BPF_W   + BPF_ABS, LC_ETHER_FRAME_TAG_OFFSET),	\
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_TAG, 0, 3),			\
	BPF_STMT(BPF_LD  + BPF_H   + BPF_ABS, LC_ETHER_FRAME_CHAN_OFFSET),	\
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   (chan), 0, 1),			\
	BPF_STMT(BPF_RET + BPF_K,             LC_ETHER_FRAME_MAX),		\
	BPF_STMT(BPF_RET + BPF_K,             0)				\
}

#define LC_ETHER_FILTER_NO_SRC_LEN 8

/*
 * IEEE 802.11 frame control constants for filter initializer.
 */
enum {
	LC_IEEE80211_FC0_TYPE_MASK	= 0x0c,
	LC_IEEE80211_FC0_SUBTYPE_MASK	= 0xf0,
	LC_IEEE80211_FC0_MASK		= LC_IEEE80211_FC0_TYPE_MASK
					| LC_IEEE80211_FC0_SUBTYPE_MASK
};

enum {
	LC_IEEE80211_FC0_TYPE_DATA	= 0x08,
	LC_IEEE80211_FC0_SUBTYPE_DATA	= 0x00,
	LC_IEEE80211_FC0_TYPE		= LC_IEEE80211_FC0_TYPE_DATA
					| LC_IEEE80211_FC0_SUBTYPE_DATA
};

/*
 * IEEE 802.11 frame offset constants for filter initializer.
 */
enum {
	LC_IEEE80211_FRAME_FC_OFFSET	= offsetof(struct lc_ieee80211_frame_hdr, hdr)
					+ offsetof(struct lc_ieee80211_hdr, fc),
	LC_IEEE80211_FRAME_SRC_OFFSET	= offsetof(struct lc_ieee80211_frame_hdr, hdr)
					+ offsetof(struct lc_ieee80211_hdr, src),
	LC_IEEE80211_FRAME_TAG_OFFSET	= offsetof(struct lc_ieee80211_frame_hdr, lc)
					+ offsetof(struct lc_hdr, tag),
	LC_IEEE80211_FRAME_CHAN_OFFSET	= offsetof(struct lc_ieee80211_frame_hdr, lc)
					+ offsetof(struct lc_hdr, chan)
};

/*
 * IEEE 802.11 read filter initializer.
 */
#define LC_IEEE80211_FILTER(src, chan) {					\
    BPF_STMT(BPF_LD  + BPF_B   + BPF_ABS, LC_IEEE80211_FRAME_FC_OFFSET),	\
    BPF_STMT(BPF_ALU + BPF_AND + BPF_K,   LC_IEEE80211_FC0_MASK),		\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_IEEE80211_FC0_TYPE, 0, 9),		\
    BPF_STMT(BPF_LD  + BPF_W   + BPF_ABS, LC_IEEE80211_FRAME_SRC_OFFSET + 2),	\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_ADDR_W(src), 0, 7),		\
    BPF_STMT(BPF_LD  + BPF_H   + BPF_ABS, LC_IEEE80211_FRAME_SRC_OFFSET),	\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_ADDR_H(src), 0, 5),		\
    BPF_STMT(BPF_LD  + BPF_W   + BPF_ABS, LC_IEEE80211_FRAME_TAG_OFFSET),	\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_TAG, 0, 3),			\
    BPF_STMT(BPF_LD  + BPF_H   + BPF_ABS, LC_IEEE80211_FRAME_CHAN_OFFSET),	\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   (chan), 0, 1),			\
    BPF_STMT(BPF_RET + BPF_K,             LC_IEEE80211_FRAME_MAX),		\
    BPF_STMT(BPF_RET + BPF_K,             0)					\
}

#define LC_IEEE80211_FILTER_LEN 13

/* addr.c */
extern const uint8_t LC_ADDR_BROADCAST[LC_ADDR_LEN];

int lc_addr_parse(uint8_t *, const char *);
int lc_addr_is_broadcast(const uint8_t *);

/*
 * packet device context.
 */
struct lc_dev {
	int	fd;			/* socket/device file descriptor */
	int	r, w;			/* read/write mode flags */

	int	chan;			/* linkcat-specific virtual channel */
	uint8_t	dst[LC_ADDR_LEN];	/* destination device address */
	uint8_t	src[LC_ADDR_LEN];	/* source device address */

	char	iface[IFNAMSIZ];	/* interface name */
	enum	lc_dlt dlt;		/* data-link level type */
	uint8_t	hw_addr[LC_ADDR_LEN];	/* local device address */
};

/*
 * Initializes a device context with the given interface, channel,
 * source address and destination address.
 * Returns 0 on success, -1 otherwise.
 */
int	lc_open(struct lc_dev *, const char *, int, const char *, const char *);

/*
 * Reads at most LC_DATA_SIZE bytes from a linkcat device.
 * Returns the number of bytes read (excluding packet data) on success,
 * 0 otherwise.
 */
ssize_t	lc_read(struct lc_dev *, void *, size_t);

/*
 * Writes at most LC_DATA_SIZE through a linkcat device.
 * Returns the number of bytes written (including packet data)
 * on success, 0 otherwise.
 */
ssize_t lc_write(struct lc_dev *, const void *, size_t);

/*
 * Closes a device context.
 */
void	lc_close(struct lc_dev *);

#endif
