#ifndef _LC_H_
#define _LC_H_

#include <stddef.h>
#include <stdint.h>

/*
 * Supported data-link level types.
 */
enum lc_dlt {
	LC_DLT_EN10MB		= 1,		/* Ethernet (10Mb) */
	LC_DLT_IEEE802_11	= 105		/* IEEE 802.11 wireless */
};

#define LC_ETHERTYPE		0x01FF		/* linkcat ethertype */
#define LC_ETHER_ADDR_LEN	6		/* Ethernet address length */

/*
 * Ethernet header.
 */
struct lc_ether_hdr {
	uint8_t		dst[LC_ETHER_ADDR_LEN];	/* destination address */
	uint8_t		src[LC_ETHER_ADDR_LEN];	/* source address */
	uint16_t	type;			/* ethertype */
} __packed;

#define LC_IEEE80211_ADDR_LEN 6			/* IEEE 802.11 address length */

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
#define LC_DATA_SIZE	1024			/* linkcat data block size */

/*
 * linkcat payload.
 */
struct lc_payload {
	uint32_t	tag;			/* linkcat tag */
	uint16_t	chan;			/* linkcat-specific virtual channel */
	uint16_t	size;			/* data size */
	uint8_t		data[LC_DATA_SIZE];	/* data block */
} __packed;

/*
 * linkcat Ethernet frame.
 */
struct lc_ether_frame {
	struct ether_hdr hdr;			/* Ethernet header */
	struct lc_payload payload;		/* linkcat payload */
} __packed;

/*
 * linkcat IEEE 802.11 frame.
 */
struct lc_ieee80211_frame {
	struct ieee80211_hdr hdr;		/* IEEE 802.11 header */
	struct lc_payload payload;		/* linkcat payload */
} __packed;

/*
 * Frame offset/size constants for filter initializers.
 */
#define LC_PAYLOAD_TAG_OFFSET							\
    (offsetof(struct lc_payload, tag))

#define LC_PAYLOAD_CHAN_OFFSET							\
    (offsetof(struct lc_payload, chan))

#define LC_ETHER_FRAME_DST_OFFSET						\
    (offsetof(struct lc_ether_frame, dst))

#define LC_ETHER_FRAME_TYPE_OFFSET						\
    (offsetof(struct lc_ether_frame, type))

#define LC_ETHER_FRAME_TAG_OFFSET						\
    (offsetof(struct lc_ether_frame, payload) + LC_PAYLOAD_TAG_OFFSET)

#define LC_ETHER_FRAME_CHAN_OFFSET						\
    (offsetof(struct lc_ether_frame, payload) + LC_PAYLOAD_CHAN_OFFSET)

#define LC_IEEE80211_FRAME_DST_OFFSET						\
    (offsetof(struct lc_ieee80211_frame, dst))

#define LC_IEEE80211_FRAME_TAG_OFFSET						\
    (offsetof(struct lc_ieee80211_frame, payload) + LC_PAYLOAD_TAG_OFFSET)

#define LC_IEEE80211_FRAME_CHAN_OFFSET						\
    (offsetof(struct lc_ieee80211_frame, payload) + LC_PAYLOAD_CHAN_OFFSET)

#define LC_ADDR_W(a) (((a)[2] << 24) | ((a)[3] << 16) | ((a)[4] << 8) | (a)[5])
#define LC_ADDR_H(a) (((a)[0] << 8)  |  (a)[1])

/*
 * Ethernet read filter initializer.
 */
#define LC_ETHER_FILTER(dst, chan) {						\
    BPF_STMT(BPF_LD  + BPF_W   + BPF_ABS, LC_ETHER_FRAME_DST_OFFSET + 2),	\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_ADDR_W(dst), 2, 11)		\
    BPF_STMT(BPF_LD  + BPF_H   + BPF_ABS, LC_ETHER_FRAME_DST_OFFSET),		\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_ADDR_H(dst), 4, 11),		\
    BPF_STMT(BPF_LD  + BPF_H   + BPF_ABS, LC_ETHER_FRAME_TYPE_OFFSET),		\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_ETHERTYPE, 6, 11),			\
    BPF_STMT(BPF_LD  + BPF_W   + BPF_ABS, LC_ETHER_FRAME_TAG_OFFSET),		\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_TAG, 8, 11),			\
    BPF_STMT(BPF_LD  + BPF_H   + BPF_ABS, LC_ETHER_FRAME_CHAN_OFFSET),		\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   (chan), 10, 11),			\
    BPF_STMT(BPF_RET + BPF_K,             sizeof(struct lc_ether_frame)),	\
    BPF_STMT(BPF_RET + BPF_K,             0)					\
}

/*
 * IEEE 802.11 read filter initializer.
 */
#define LC_IEEE80211_FILTER(dst, chan) {					\
    BPF_STMT(BPF_LD  + BPF_W   + BPF_ABS, LC_IEEE80211_FRAME_DST_OFFSET + 2),	\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_ADDR_W(dst), 2, 9),		\
    BPF_STMT(BPF_LD  + BPF_H   + BPF_ABS, LC_IEEE80211_FRAME_DST_OFFSET),	\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_ADDR_H(dst), 4, 9),		\
    BPF_STMT(BPF_LD  + BPF_W   + BPF_ABS, LC_IEEE80211_FRAME_TAG_OFFSET),	\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_TAG, 6, 9),			\
    BPF_STMT(BPF_LD  + BPF_H   + BPF_ABS, LC_IEEE80211_FRAME_CHAN_OFFSET),	\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   (chan), 8, 9),			\
    BPF_STMT(BPF_RET + BPF_K,             sizeof(struct lc_ieee80211_frame)),	\
    BPF_STMT(BPF_RET + BPF_K,             0)					\
}

#define LC_DEV_ADDR_LEN 6			/* linkcat device address length */

/*
 * linkcat device context.
 */
struct lc_dev {
	int	fd;				/* socket/device file descriptor */
	enum	lc_dlt dlt;			/* data-link level type */
	uint8_t	addr[LC_DEV_ADDR_LEN];		/* device hardware address */
};

/*
 * linkcat device routines.
 */
int	lc_open(struct lc_dev *, const char *);
ssize_t	lc_read(struct lc_dev *, void *, size_t);
ssize_t lc_write(struct lc_dev, const void *, size_t);
void	lc_close(struct lc_dev *);

#endif
