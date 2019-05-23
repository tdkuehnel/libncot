#ifndef _NCOT_ERROR_
#define _NCOT_ERROR_

#include <string.h>

#include "log.h"

#define SOCKET_ERR(err, s)  if(err==-1) {NCOT_LOG_ERROR("%s: %s\n", s, strerror(err));return(1);}
#define SOCKET_NERR(err, s) if(err==-1) {NCOT_LOG_ERROR("%s: %s\n", s, strerror(err));return(-1);}

#endif
