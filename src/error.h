#ifndef _NCOT_ERROR_
#define _NCOT_ERROR_

#include <string.h>
#include <gnutls/gnutls.h>

#include "ncot.h"
#include "log.h"

#define NCOT_ERROR -1
#define NCOT_OK 0

#define NCOT_ERROR_IF_NULL(val, fmt, ...) if(val==NULL) {NCOT_LOG_ERROR(fmt, ## __VA_ARGS__); return NCOT_ERROR;}

#define SOCKET_ERR(err, s)  if(err==-1) {NCOT_LOG_ERROR("%s: %s\n", s, strerror(err));return(1);}
#define SOCKET_NERR(err, s) if(err==-1) {NCOT_LOG_ERROR("%s: %s\n", s, strerror(err));return(-1);}
#define FD_ERROR(err, s) if(err==-1) {NCOT_LOG_ERROR("%s: %s\n", s, strerror(err));return(NULL);}

#define SOCKET_ERR_BREAK(err, s)  if(err==-1) {NCOT_LOG_ERROR("%s: %s\n", s, strerror(err));break;}

#define GNUTLS_ERROR(err, s)  if(err!=GNUTLS_E_SUCCESS) {NCOT_LOG_ERROR("%s: %s\n", s, gnutls_strerror(err));return -1;}

#define ERROR_MESSAGE_RETURN(s) {NCOT_LOG_ERROR("%s\n", s);return -1;}

#define RETURN_FAIL(s) {NCOT_LOG_ERROR("%s\n", s);return -1;}
#define RETURN_IF_FAIL(i) if(i!=0){return i;}
#define RETURN_IF_NULL(p, s) if(p == NULL){NCOT_LOG_ERROR("%s\n", s);return;}
#define RETURN_FAIL_IF_NULL(p, s) if(p == NULL){NCOT_LOG_ERROR("%s\n", s);return -1;}
#define RETURN_NULL_IF_NULL(p, s) if(p == NULL){NCOT_LOG_ERROR("%s\n", s);return NULL;}
#define RETURN_ZERO_IF_NULL(p, s) if(p == NULL){NCOT_LOG_ERROR("%s\n", s);return 0;}
#define RETURN_ERROR_IF_NULL(p, s) if(p == NULL){NCOT_LOG_ERROR("%s\n", s);return NCOT_ERROR;}

#define RETURN_ERROR_STR(s) {NCOT_LOG_ERROR("%s\n", s);return;}
#define RETURN_WARNING_STR(s) {NCOT_LOG_WARNING("%s\n", s);return;}

#ifdef _WIN32
#include <winsock2.h>
#include <windef.h>
#define SOCKET_ERROR_FAIL(err, s)  if(err==SOCKET_ERROR) {NCOT_LOG_ERROR("%s: %i\n", s, WSAGetLastError());return(1);}
#define INVALID_SOCKET_ERROR(err, s)  if(err==INVALID_SOCKET) {NCOT_LOG_ERROR("%s: %i\n", s, WSAGetLastError());return(1);}
#endif

#endif
