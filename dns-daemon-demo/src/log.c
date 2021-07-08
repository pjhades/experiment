#include "log.h"

void log_init(const char *ident)
{
    openlog(ident, LOG_NDELAY | LOG_PID, LOG_USER);
}
