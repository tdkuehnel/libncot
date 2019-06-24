#ifndef _NCOT_LOG_
#define _NCOT_LOG_

#include <stdlib.h>

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define NCOT_LOG_LEVEL_QUIET   0
#define NCOT_LOG_LEVEL_FATAL   8
#define NCOT_LOG_LEVEL_ERROR   16
#define NCOT_LOG_LEVEL_WARNING 24
#define NCOT_LOG_LEVEL_INFO    32
#define NCOT_LOG_LEVEL_VERBOSE 40
#define NCOT_LOG_LEVEL_DEBUG   48 /* debug.h has own macros for debugging*/

#define NCOT_LOG_LEVEL_DEFAULT 32

/* Function pointer to log function */

typedef void (*ncot_log_pointer)(int, const char *, ...);
extern ncot_log_pointer log_ptr;

typedef void (*ncot_log_flush_pointer)();
extern ncot_log_flush_pointer log_flush_ptr;

extern ncot_log_pointer log_ptr;
extern ncot_log_pointer log_buffered_ptr;
extern ncot_log_flush_pointer log_buffer_flush_ptr;

#define NCOT_LOG(level, fmt, ...)					\
  if (log_ptr != NULL) { (*log_ptr)(level, fmt,  ## __VA_ARGS__); }
#define NCOT_LOG_BUFFERED(level, fmt, ...)					\
  if (log_buffered_ptr != NULL) { (*log_buffered_ptr)(level, fmt,  ## __VA_ARGS__); }

#define NCOT_LOG_VERBOSE(fmt, ...) NCOT_LOG(NCOT_LOG_LEVEL_VERBOSE, fmt, ## __VA_ARGS__);
#define NCOT_LOG_INFO(fmt, ...) NCOT_LOG(NCOT_LOG_LEVEL_INFO, fmt, ## __VA_ARGS__);
#define NCOT_LOG_ERROR(fmt, ...) NCOT_LOG(NCOT_LOG_LEVEL_ERROR, fmt, ## __VA_ARGS__);
#define NCOT_LOG_WARNING(fmt, ...) NCOT_LOG(NCOT_LOG_LEVEL_WARNING, fmt, ## __VA_ARGS__);

#define NCOT_LOG_INFO_BUFFERED(fmt, ...) NCOT_LOG_BUFFERED(NCOT_LOG_LEVEL_INFO, fmt, ## __VA_ARGS__);
/*#define NCOT_LOG_INFO_BUFFERED(fmt, ...) if (log_buffered_ptr != NULL) { (*log_buffered_ptr)(NCOT_LOG_LEVEL_INFO, fmt,  ## __VA_ARGS__); }*/
#define NCOT_LOG_INFO_BUFFER_FLUSH() if (log_buffered_ptr != NULL) { (*log_buffer_flush_ptr)(); }

void ncot_log_init(int level);
int ncot_log_set_logfile(const char *filename);
void ncot_log_done();

/* Our different log functions */
void ncot_log_logfile( int level, const char *fmt, ... );
void ncot_log_logfile_buffer_flush();
void ncot_log_logfile_buffered( int level, const char *fmt, ... );
void ncot_log_printf_buffer_flush();
void ncot_log_printf_buffered( int level, const char *fmt, ... );
void ncot_log_printf( int level, const char *fmt, ... );
void ncot_log_hex (char *desc, void *addr, int len);

#endif
