#ifndef _NCOT_H_
#define _NCOT_H_

#include <uuid.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <gnutls/gnutls.h>

#define LISTEN_BACKLOG 12

typedef enum ncot_connection_type {
  NCOT_CONN_NODE,
  NCOT_CONN_LISTEN
} ncot_connection_type_t;

typedef enum ncot_connection_status {
  NCOT_CONN_CONNECTED,
  NCOT_CONN_CLOSED,
  NCOT_CONN_INIT
} ncot_connection_status_t;
  
typedef struct ncot_connection_t {
  int fd;
  struct sockaddr_in sa_serv;
  struct sockaddr_in sa_cli;
  socklen_t client_len;
  char topbuf[512];
  gnutls_session_t session;
  gnutls_anon_server_credentials_t anoncred;  
  ncot_connection_type_t type;
  ncot_connection_status_t status;
} ncot_connection_t;

typedef struct ncot_node_t {
  ncot_connection_t left;
  ncot_connection_t right;
  uuid_t *uuid;
} ncot_node_t;

typedef struct ncot_identity_t {
  uuid_t *uuid;
} ncot_identity_t;

ncot_node_t *ncot_node_new();
void ncot_node_free(ncot_node_t **pnode);
void ncot_node_init(ncot_node_t *node);

ncot_identity_t *ncot_identity_new();
void ncot_identity_free(ncot_identity_t **pidentity);
void ncot_identity_init(ncot_identity_t *identity);

void ncot_init();
void ncot_done();

#endif
