#ifndef _NCOT_H_
#define _NCOT_H_

#include <uuid.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <gnutls/gnutls.h>

#include "context.h"

typedef struct ncot_identity_t {
  uuid_t *uuid;
} ncot_identity_t;

int
ncot_control_connection_authenticate(struct ncot_connection *connection);
void
ncot_set_fds(struct ncot_context *context, fd_set *rfds, fd_set *wfds);
void
ncot_process_fd(struct ncot_context *context, int r, fd_set *rfds, fd_set *wfds);

ncot_identity_t *ncot_identity_new();
void ncot_identity_free(ncot_identity_t **pidentity);
void ncot_identity_init(ncot_identity_t *identity);

void ncot_init();
void ncot_done();

#endif
