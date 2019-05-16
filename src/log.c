#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "log.h"

#define DEBUG 0
#include "debug.h"

int nct_log_level = NCT_LOG_LEVEL_DEFAULT;

nct_log_pointer log_ptr = NULL;

void nct_log_printf( int level, const char *fmt, ... ) {
  NCT_DEBUG("called log with level: %d, current log_level: %d\n", level, nct_log_level);
  if ( level <= nct_log_level ) {
    va_list vl;
    va_start(vl, fmt);
    vprintf(fmt, vl);
    va_end(vl);
  }
}

void nct_log_init(int level) {
  log_ptr = &nct_log_printf;
  nct_log_level = level * 8;
  
  NCT_DEBUG("set log level to: %d\n", nct_log_level);
}

void nct_log_done() {
}
