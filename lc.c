#include <sys/select.h>

#include <err.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "lc.h"
#include "log.h"

static void usage(void);

int
main(int argc, char **argv)
{
	unsigned long	 chan		= 0;
	const char	*ifname		= NULL;
	const char	*destination	= NULL;

	int ch;
	while ((ch = getopt(argc, argv, "lvc:")) != -1) {
		switch (ch) {
		case 'v':
			if (log_verbose < 2)
				log_verbose++;
			else
				usage();
			break;
		case 'c':
			chan = strtoul(optarg, NULL, 10);
			if (LC_CHAN_MAX < chan) {
				warnx("channel value must lie between 0 and 65536");
				usage();
			}
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 2)
		usage();

	if_name = argv[0];
	destination = argv[1];

	log_info("opening linkcat device on channel %d, interface %s",
	    chan, if_name);
	struct lc_dev dev;
	if (lc_open(&dev, chan, if_name) == -1)
		err(1, "lc_open");

	log_info("closing linkcat device");
	lc_close(&dev);

	return 0;
}

static void
usage(void)
{
	fprintf(stderr, "usage: lc [-vv] [-c channel] <interface> <destination>\n");
	exit(1);
}
