#ifndef _NCOT_ERROR_
#define _NCOT_ERROR_

#include <string.h>
#include <gnutls/gnutls.h>

#include "log.h"

#define SOCKET_ERR(err, s)  if(err==-1) {NCOT_LOG_ERROR("%s: %s\n", s, strerror(err));return(1);}
#define SOCKET_NERR(err, s) if(err==-1) {NCOT_LOG_ERROR("%s: %s\n", s, strerror(err));return(-1);}

#define SOCKET_ERR_BREAK(err, s)  if(err==-1) {NCOT_LOG_ERROR("%s: %s\n", s, strerror(err));break;}

#define GNUTLS_ERROR(err, s)  if(err!=GNUTLS_E_SUCCESS) {NCOT_LOG_ERROR("%s: %s\n", s, gnutls_strerror(err));return -1;}

#define ERROR_MESSAGE_RETURN(s) {NCOT_LOG_ERROR("%s\n", s);return -1;}

#define RETURN_FAIL_IF_NULL(p, s) if(p == NULL){NCOT_LOG_ERROR("%s\n", s);return -1;}
#define RETURN_NULL_IF_NULL(p, s) if(p == NULL){NCOT_LOG_ERROR("%s\n", s);return NULL;}

#endif
