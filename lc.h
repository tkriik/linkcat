#ifndef _LC_H_
#define _LC_H_

#include <sys/endian.h>
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

#define LC_ETHERTYPE		0x01FF		/* linkcat ethertype */
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
#define LC_DATA_SIZE	1024			/* linkcat data block size */
#define LC_CHAN_MAX	65535			/* maximum linkcat channel value */

/*
 * linkcat payload.
 */
struct lc_payload {
	uint32_t	tag;			/* linkcat tag */
	uint16_t	chan;			/* linkcat-specific virtual channel */
	uint16_t	size;			/* data size */
	uint8_t		data[LC_DATA_SIZE];	/* data block */
} __packed;

#define LC_PAYLOAD_MIN (sizeof(struct lc_payload) - LC_DATA_SIZE)

/*
 * linkcat Ethernet frame.
 */
struct lc_ether_frame {
	struct lc_ether_hdr hdr;		/* Ethernet header */
	struct lc_payload payload;		/* linkcat payload */
} __packed;

/*
 * linkcat IEEE 802.11 frame.
 */
struct lc_ieee80211_frame {
	struct lc_ieee80211_hdr hdr;		/* IEEE 802.11 header */
	struct lc_ieee8022_llc_hdr llc;		/* LLC header */
	struct lc_payload payload;		/* linkcat payload */
} __packed;

/*
 * Minimum frame sizes.
 */
enum {
	LC_ETHER_FRAME_MIN	= sizeof(struct lc_ether_hdr)
				+ LC_PAYLOAD_MIN,
	LC_IEEE80211_FRAME_MIN	= sizeof(struct lc_ieee80211_hdr)
				+ sizeof(struct lc_ieee8022_llc_hdr)
				+ LC_PAYLOAD_MIN
};

/*
 * Utility macros for device address comparison in filter initializers.
 */
#define LC_ADDR_W(a) (((a)[2] << 24) | ((a)[3] << 16) | ((a)[4] << 8) | (a)[5])
#define LC_ADDR_H(a) (((a)[0] << 8)  |  (a)[1])

/*
 * Frame offset constants for Ethernet filter initializer.
 */
enum {
	LC_ETHER_FRAME_SRC_OFFSET	= offsetof(struct lc_ether_frame, hdr)
					+ offsetof(struct lc_ether_hdr, src),
	LC_ETHER_FRAME_TYPE_OFFSET	= offsetof(struct lc_ether_frame, hdr)
					+ offsetof(struct lc_ether_hdr, type),
	LC_ETHER_FRAME_TAG_OFFSET	= offsetof(struct lc_ether_frame, hdr)
					+ offsetof(struct lc_payload, tag),
	LC_ETHER_FRAME_CHAN_OFFSET	= offsetof(struct lc_ether_frame, payload)
					+ offsetof(struct lc_payload, chan)
};

/*
 * Ethernet read filter initializer.
 */
#define LC_ETHER_FILTER(src, chan) {						\
    BPF_STMT(BPF_LD  + BPF_W   + BPF_ABS, LC_ETHER_FRAME_SRC_OFFSET + 2),	\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_ADDR_W(src), 0, 9),		\
    BPF_STMT(BPF_LD  + BPF_H   + BPF_ABS, LC_ETHER_FRAME_SRC_OFFSET),		\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_ADDR_H(src), 0, 7),		\
    BPF_STMT(BPF_LD  + BPF_H   + BPF_ABS, LC_ETHER_FRAME_TYPE_OFFSET),		\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_ETHERTYPE, 0, 5),			\
    BPF_STMT(BPF_LD  + BPF_W   + BPF_ABS, LC_ETHER_FRAME_TAG_OFFSET),		\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_TAG, 0, 3),			\
    BPF_STMT(BPF_LD  + BPF_H   + BPF_ABS, LC_ETHER_FRAME_CHAN_OFFSET),		\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   (chan), 0, 1),			\
    BPF_STMT(BPF_RET + BPF_K,             sizeof(struct lc_ether_frame)),	\
    BPF_STMT(BPF_RET + BPF_K,             0)					\
}

#define LC_ETHER_FILTER_LEN 12

/*
 * Ethernet read filter initializer (without source address).
 */
#define LC_ETHER_FILTER_NO_SRC(chan) {					\
    BPF_STMT(BPF_LD  + BPF_H   + BPF_ABS, LC_ETHER_FRAME_TYPE_OFFSET),		\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_ETHERTYPE, 0, 5),			\
    BPF_STMT(BPF_LD  + BPF_W   + BPF_ABS, LC_ETHER_FRAME_TAG_OFFSET),		\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   LC_TAG, 0, 3),			\
    BPF_STMT(BPF_LD  + BPF_H   + BPF_ABS, LC_ETHER_FRAME_CHAN_OFFSET),		\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   (chan), 0, 1),			\
    BPF_STMT(BPF_RET + BPF_K,             sizeof(struct lc_ether_frame)),	\
    BPF_STMT(BPF_RET + BPF_K,             0)					\
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
	LC_IEEE80211_FRAME_FC_OFFSET	= offsetof(struct lc_ieee80211_frame, hdr)
					+ offsetof(struct lc_ieee80211_hdr, fc),
	LC_IEEE80211_FRAME_SRC_OFFSET	= offsetof(struct lc_ieee80211_frame, hdr)
					+ offsetof(struct lc_ieee80211_hdr, src),
	LC_IEEE80211_FRAME_TAG_OFFSET	= offsetof(struct lc_ieee80211_frame, payload)
					+ offsetof(struct lc_payload, tag),
	LC_IEEE80211_FRAME_CHAN_OFFSET	= offsetof(struct lc_ieee80211_frame, payload)
					+ offsetof(struct lc_payload, chan)
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
    BPF_STMT(BPF_RET + BPF_K,             sizeof(struct lc_ieee80211_frame)),	\
    BPF_STMT(BPF_RET + BPF_K,             0)					\
}

#define LC_IEEE80211_FILTER_LEN 13

/*
 * IEEE 802.11 read filter initializer (without source address).
 */
#define LC_IEEE80211_FILTER_NO_SRC(chan) {					\
	{ 0x30, 0, 0, 0x00000000 }, \
	{ 0x54, 0, 0, 0x000000fc }, \
	{ 0x15, 0, 5, 0x00000008 }, \
	{ 0x20, 0, 0, 0x0000000c }, \
	{ 0x15, 0, 3, 0x54a36a13 }, \
	{ 0x28, 0, 0, 0x0000000a }, \
	{ 0x15, 0, 1, 0x0000101c }, \
	{ 0x6, 0, 0, 2048 }, \
	{ 0x6, 0, 0, 0x00000000 }, \
}

#define LC_IEEE80211_FILTER_NO_SRC_LEN 9

/* addr.c */
extern const uint8_t LC_ADDR_BROADCAST[LC_ADDR_LEN];

int lc_addr_parse(uint8_t *, const char *);
int lc_addr_is_broadcast(const uint8_t *);

/*
 * linkcat packet device context.
 */
struct lc_dev {
	int	fd;			/* socket/device file descriptor */
	int	r, w;			/* read/write mode flags */

	int	chan;			/* linkcat-specific virtual channel */
	uint8_t	from_addr[LC_ADDR_LEN];	/* source device address */
	uint8_t	to_addr[LC_ADDR_LEN];	/* destination device address */

	enum	lc_dlt dlt;		/* data-link level type */
	uint8_t	this_addr[LC_ADDR_LEN];	/* local device address */
};

/* dev_*.c */
int	lc_open(struct lc_dev *, const char *, int, const char *, const char *);
ssize_t	lc_read(struct lc_dev *, void *, size_t);
ssize_t lc_write(struct lc_dev *, const void *, size_t);
void	lc_close(struct lc_dev *);

#endif
