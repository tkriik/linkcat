#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "lc.h"

const uint8_t LC_ADDR_BROADCAST[LC_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

int
lc_addr_parse(uint8_t *a, const char *s)
{
	int nmatch = sscanf(s,
	    "%" SCNx8 ":" "%" SCNx8 ":" "%" SCNx8 ":"
	    "%" SCNx8 ":" "%" SCNx8 ":" "%" SCNx8,
	    &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]);

	if (nmatch != LC_ADDR_LEN)
		return -1;

	return 0;
}

int
lc_addr_is_broadcast(const uint8_t *a)
{
	return memcmp(a, LC_ADDR_BROADCAST, LC_ADDR_LEN) == 0;
}
