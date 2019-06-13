#ifndef _NCOT_INIT_H_
#define _NCOT_INIT_H_

#define GNUTLS_LOG_LEVEL 0

#ifdef _WIN32
int ncot_socket_pair(int *fd1, int *fd2);
#endif
void ncot_init();
void ncot_done();
void print_logs(int level, const char* msg);
int ncot_daemonize();

#endif
