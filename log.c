#include <err.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "log.h"

static void log_args(int, const char *, va_list);

int log_verbose = 0;

void
log_info(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_args(1, fmt, args);
	va_end(args);
}

void
log_debug(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_args(2, fmt, args);
	va_end(args);
}

static void
log_args(int level, const char *fmt, va_list args)
{
	static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

	int rc;

	if (log_verbose < level)
		return;

	rc = pthread_mutex_lock(&mtx);
	if (rc != 0)
		err(1, "pthread_mutex_lock");

	vwarnx(fmt, args);

	rc = pthread_mutex_unlock(&mtx);
	if (rc != 0)
		err(1, "pthread_mutex_unlock");
}
