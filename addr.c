#include <string.h>

#include "lc.h"

const struct lc_addr LC_ADDR_BROADCAST = {
	.data = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
};

int
lc_addr_parse(const char *s, struct lc_addr *addr)
{
	int nmatched = sscanf("%02x:%02x:%02x:%02x:%02x:%02x",
	    addr.data[0], addr.data[1], addr.data[2],
	    addr.data[3], addr.data[4], addr.data[5]);

	if (nmatched != sizeof(addr.data))
		return -1;

	return 0;
}

int
lc_addr_is_broadcast(struct lc_addr addr)
{
	return memcmp(LC_ADDR_BROADCAST.data, addr.data, LC_ADDR_LEN) == 0;
}
