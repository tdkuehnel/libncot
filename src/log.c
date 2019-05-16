#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "log.h"

#define DEBUG 0
#include "debug.h"

int ncot_log_level = NCOT_LOG_LEVEL_DEFAULT;

ncot_log_pointer log_ptr = NULL;
const char* logfilename = {"ncot.log"};

void ncot_log_printf( int level, const char *fmt, ... ) {
  NCOT_DEBUG("called log with level: %d, current log_level: %d\n", level, ncot_log_level);
  if ( level <= ncot_log_level ) {
    va_list vl;
    va_start(vl, fmt);
    vprintf(fmt, vl);
    va_end(vl);
  }
}

void ncot_log_logfile( int level, const char *fmt, ... ) {
  int fd, i;
  struct stat logfilestat;
  if ( level <= ncot_log_level ) {
    va_list vl;
    i = stat(logfilename, &logfilestat);
    if (i == 0) {
      fd = open(logfilename, O_APPEND|O_SYNC|O_WRONLY );
    } else {
      fd = creat(logfilename, S_IRWXU);
    }
    if (fd > 0) {
      va_start(vl, fmt);
      vdprintf(fd, fmt, vl);
      va_end(vl);
      close(fd);
    }
  }
}

void ncot_log_set_logfile() {
  int i;
  struct stat logfilestat;
  i = stat(logfilename, &logfilestat);
  if (i == 0) {
    unlink(logfilename);
  }
  log_ptr = &ncot_log_logfile;
}

void ncot_log_init(int level) {
  log_ptr = &ncot_log_printf;
  ncot_log_level = level * 8;
  
  NCOT_DEBUG("set log level to: %d\n", ncot_log_level);
}

void ncot_log_done() {
}
