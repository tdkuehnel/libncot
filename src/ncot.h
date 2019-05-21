#ifndef _NCOT_H_
#define _NCOT_H_

#include <uuid.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <gnutls/gnutls.h>

typedef struct ncot_identity_t {
  uuid_t *uuid;
} ncot_identity_t;

ncot_identity_t *ncot_identity_new();
void ncot_identity_free(ncot_identity_t **pidentity);
void ncot_identity_init(ncot_identity_t *identity);

void ncot_init();
void ncot_done();

#endif
