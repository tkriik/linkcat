#include <err.h>
#include <stdarg.h>

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
	if (log_verbose < level)
		return;

	vwarnx(fmt, args);
}
