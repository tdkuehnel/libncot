#ifndef _NCOT_LOG_
#define _NCOT_LOG_

#include <stdlib.h>

#define NCOT_LOG_LEVEL_QUIET   0
#define NCOT_LOG_LEVEL_FATAL   8
#define NCOT_LOG_LEVEL_ERROR   16
#define NCOT_LOG_LEVEL_WARNING 24
#define NCOT_LOG_LEVEL_INFO    32
#define NCOT_LOG_LEVEL_VERBOSE 40
#define NCOT_LOG_LEVEL_DEBUG   48

#define NCOT_LOG_LEVEL_DEFAULT 32

#define NCOT_LOG(level, fmt, ...)					\
  if (log_ptr != NULL) { (*log_ptr)(level, fmt,  ## __VA_ARGS__); }

#define NCOT_LOG_INFO(fmt, ...) NCOT_LOG(NCOT_LOG_LEVEL_INFO, fmt, ## __VA_ARGS__);
#define NCOT_LOG_ERROR(fmt, ...) NCOT_LOG(NCOT_LOG_LEVEL_ERROR, fmt, ## __VA_ARGS__);
#define NCOT_LOG_WARNING(fmt, ...) NCOT_LOG(NCOT_LOG_LEVEL_WARNING, fmt, ## __VA_ARGS__);

/* Function pointer to log function */

typedef void (*ncot_log_pointer)(int, const char *, ...);

extern ncot_log_pointer log_ptr;

void ncot_log_init(int level);
int ncot_log_set_logfile(const char *filename);
void ncot_log_done();

/* Our different log functions */

void ncot_log_printf( int level, const char *fmt, ... );
void ncot_log_hex (char *desc, void *addr, int len);

#endif
