#ifndef _NCOT_INIT_H_
#define _NCOT_INIT_H_

#define GNUTLS_LOG_LEVEL 0

void ncot_init();
void ncot_done();
void print_logs(int level, const char* msg);

#endif
