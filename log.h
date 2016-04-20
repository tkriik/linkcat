#ifndef _LC_LOG_H_
#define _LC_LOG_H_

void log_info(const char *, ...);
void log_debug(const char *, ...);

extern int log_verbose;

#endif
