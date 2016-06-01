#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "lc.h"

/* I/O thread workers. */
void *lc_reader(void *);
void *lc_writer(void *);

void usage(void);

int
main(int argc, char **argv)
{
	const char	*iface	= NULL;
	const char	*dst	= NULL;
	const char	*src	= NULL;
	const char	*bssid	= NULL;
	unsigned long	 chan	= 0;

	int ch;
	while ((ch = getopt(argc, argv, "i:c:t:f:b:")) != -1) {
		switch (ch) {
		case 'i':
			iface = optarg;
			break;
		case 'c':
			chan = strtoul(optarg, NULL, 10);
			if (LC_CHAN_MAX < chan) {
				warnx("channel value must be under 65536");
				usage();
			}
			break;
		case 't':
			dst = optarg;
			break;
		case 'f':
			src = optarg;
			break;
		case 'b':
			bssid = optarg;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	/*
	 * This program isn't too useful, if it can neither
	 * send or receive packets.
	 */
	if (src == NULL && dst == NULL) {
		warnx("no source or destination address provided (-t, -f), "
		      "please specify either option or both.");
		usage();
	}

	/* Initialize a packet device context. */
	struct lc_dev dev;
	if (lc_open(&dev, iface, chan, dst, src, bssid) == -1)
		return 1;
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
	if (dev.r && dev.w) {
		pthread_t read_thrd, write_thrd;

		if (pthread_create(&read_thrd, NULL, lc_reader, &dev) != 0)
			err(1, "pthread_create");

		if (pthread_create(&write_thrd, NULL, lc_writer, &dev) != 0)
			err(1, "pthread_create");

		// TODO: statistics 
		if (pthread_join(read_thrd, NULL) != 0)
			err(1, "pthread_join");

		if (pthread_join(write_thrd, NULL) != 0)
			err(1, "pthread_join");
	} else {
		if (dev.r)
			lc_reader(&dev);
		else if (dev.w)
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
	struct lc_dev *dev = arg;

	while (1) {
		uint8_t buf[LC_DATA_SIZE];
		ssize_t nr, nw;

		nr = lc_read(dev, buf, sizeof(buf));
		if (nr == -1)
			continue;

		do {
			nw = write(STDOUT_FILENO, buf, nr);
			if (nw == -1) {
				if (errno == EINTR)
					continue;
				else
					err(1, "write");
			} else
				break;
		} while (1);
	}

	return NULL;
}

void *
lc_writer(void *arg)
{
	struct lc_dev *dev = arg;

	while (1) {
		uint8_t buf[LC_DATA_SIZE];
		ssize_t nr, nw;

		nr = read(STDIN_FILENO, buf, sizeof(buf));
		if (nr == -1) {
			if (errno == EINTR)
				continue;
			else
				err(1, "read");
		}

		if (nr == 0)
			return NULL;
		else
			nw = lc_write(dev, buf, nr);
	}

	return NULL;
}

void
usage(void)
{
	extern char *__progname;

	fprintf(stderr,
"usage: %s [-i interface] [-c channel] [-t destination_address]\n"
"          [-f source_address] [-b bssid]\n",
	    __progname);
	exit(1);
}
