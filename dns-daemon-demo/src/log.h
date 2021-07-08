#pragma once

#include <syslog.h>
#include <errno.h>
#include <string.h>

#define log_err(fmt, ...) syslog(LOG_ERR, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...) syslog(LOG_INFO, fmt, ##__VA_ARGS__)
#define log_dbg(fmt, ...) syslog(LOG_DEBUG, fmt, ##__VA_ARGS__)
/* strerror is used here for convenience since we
 * are not going to be multithreaded */
#define log_perr(fmt, ...) \
    syslog(LOG_ERR, fmt ": %s", ##__VA_ARGS__, strerror(errno))

void log_init(const char *ident);
