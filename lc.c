#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lc.h"

/* I/O thread workers. */
void *lc_reader(void *);
void *lc_writer(void *);

void usage(void);

int
main(int argc, char **argv)
{
	int		 local	= 0;
	unsigned long	 chan	= 0;
	const char	*dst	= NULL;
	const char	*src	= NULL;
	const char	*iface	= NULL;

	int ch;
	while ((ch = getopt(argc, argv, "li:c:t:f:")) != -1) {
		switch (ch) {
		case 'l':
			local = 1;
			break;
		case 'c':
			chan = strtoul(optarg, NULL, 10);
			if (LC_CHAN_MAX < chan) {
				warnx("channel value must be less than 65536");
				usage();
			}
			break;
		case 't':
			dst = optarg;
			break;
		case 'f':
			src = optarg;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	iface = argv[0];

	/*
	 * If no source or destination address provided,
	 * set both to 'any'.
	 */
	if (src == NULL && dst == NULL) {
		src = "any";
		dst = "any";
	}

	/*
	 * Convert source and/or destination with 'any' value to broadcast.
	 */
	if (src != NULL && strcmp(src, "any") == 0)
		src = "ff:ff:ff:ff:ff:ff";

	if (dst != NULL && strcmp(dst, "any") == 0)
		dst = "ff:ff:ff:ff:ff:ff";

	/* Initialize a packet device context. */
	struct lc_dev dev;
	if (lc_open(&dev, iface, chan, src, dst, local) == -1)
		return 1;

	warnx("packet device opened at %s", iface);

	/*
	 * If the source address (src) is specified,
	 * read from the socket/device and write to stdout.
	 *
	 * If the destination address (dst) is specified,
	 * read from stdin and write to the socket/device.
	 *
	 * Reading from device to stdout and writing to device from-stdin
	 * are handled in separate threads if both roles are required.
	 *
	 * TODO: signals
	 */
	if (src != NULL && dst != NULL) {
		pthread_t r_thrd, w_thrd;

		if (pthread_create(&r_thrd, NULL, lc_reader, &dev) != 0)
			err(1, "pthread_create");

		if (pthread_create(&w_thrd, NULL, lc_writer, &dev) != 0)
			err(1, "pthread_create");

		// TODO: statistics 
		if (pthread_join(r_thrd, NULL) != 0)
			err(1, "pthread_join");

		if (pthread_join(w_thrd, NULL) != 0)
			err(1, "pthread_join");
	} else {
		if (src != NULL)
			lc_reader(&dev);
		else if (dst != NULL)
			lc_writer(&dev);
		else
			err(1, "no read nor write mode set");
	}

	// TODO: set signal handler with cleanup
	lc_close(&dev);

	return 0;
}

void *
lc_reader(void *arg)
{
	struct	lc_dev *dev = arg;

	while (1)
		lc_in(dev);

	return NULL;
}

void *
lc_writer(void *arg)
{
	struct lc_dev *dev = arg;

	while (1)  {
		ssize_t nw = lc_out(dev);
		if (nw == 0)
			break;
	}

	return NULL;
}

void
usage(void)
{
	extern char *__progname;

	fprintf(stderr,
"usage: %s [-l] [-c channel] [-f source] [-t destination] <interface>\n",
	    __progname);
	exit(1);
}
