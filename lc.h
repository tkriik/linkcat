#ifndef _LC_H_
#define _LC_H_

#include <stddef.h>
#include <stdint.h>

/*
 * Suppored data-link level types.
 */
enum {
	LC_DLT_EN10MB		= 1,	/* Ethernet (10Mb) */
	LC_DLT_IEEE802_11	= 105	/* IEEE 802.11 wireless */
};

/* Falls inside the experimental ethertype range defined by IEEE. */
#define LC_ETHERTYPE 0x01FF 

#define LC_ETHER_ADDR_LEN 6

struct lc_ether_hdr {
	uint8_t		dst[LC_ETHER_ADDR_LEN];	/* destination address */
	uint8_t		src[LC_ETHER_ADDR_LEN];	/* source address */
	uint16_t	type;			/* ethertype */
} __packed;

#define LC_IEEE80211_ADDR_LEN 6

struct lc_ieee80211_hdr {
	uint8_t	fc[2];				/* frame control */
	uint8_t dur[2];				/* duration control */
	uint8_t	dst[LC_IEEE80211_ADDR_LEN];	/* destination address */
	uint8_t src[LC_IEEE80211_ADDR_LEN];	/* source address */
	uint8_t bssid[LC_IEEE80211_ADDR_LEN];	/* BSSID */
	uint8_t seq[2];				/* sequence control */
} __packed;

#define LC_DATA_SIZE 1024

struct lc_payload {
	uint16_t	chan;			/* linkcat-specific virtual channel */
	uint16_t	size;			/* data size */
	uint8_t		data[LC_DATA_SIZE];	/* data block */
} __packed;

struct lc_ether_frame {
	struct ether_hdr	hdr;
	struct lc_payload	payload;
} __packed;

struct lc_ieee80211_frame {
	struct ieee80211_hdr	hdr;
	struct lc_payload	payload;
} __packed;

#define LC_PAYLOAD_CHAN_OFFSET						\
    (offsetof(struct lc_payload, chan))

#define LC_ETHER_FRAME_CHAN_OFFSET					\
    (offsetof(struct lc_ether_frame, payload) + LC_PAYLOAD_CHAN_OFFSET)

#define LC_IEEE80211_FRAME_CHAN_OFFSET					\
    (offsetof(struct lc_ieee80211_frame, payload) + LC_PAYLOAD_CHAN_OFFSET)

#define LC_IEEE80211_FILTER(s, c) {					\
    BPF_STMT(BPF_LD  + BPF_B   + BPF_ABS, 0),				\
    BPF_STMT(BPF_ALU + BPF_AND + BPF_K,   0xfc),			\
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   0x08, 3, 8),			\
    BPF_STMT(BPF_LD  + BPF_W   + BPF_K,   12)				\
    BPF_STMT(

#define LC_DEV_ADDR_LEN 6

struct lc_dev {
	int fd;				/* Linux socket or BSD device */
	int dlt;			/* data-link level type */
	uint8_t	addr[LC_DEV_ADDR_LEN];	/* device address */
};

int	lc_open(struct lc_dev *, const char *);
ssize_t	lc_read(struct lc_dev *, void *, size_t);
ssize_t lc_write(struct lc_dev, const void *, size_t);
void	lc_close(struct lc_dev *);

#endif
