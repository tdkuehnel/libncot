#ifndef _NCOT_CONNECTION_
#define _NCOT_CONNECTION_

#include <arpa/inet.h>
#include <netinet/in.h>
#include <gnutls/gnutls.h>

#include "context.h"

/* A connection is a securely encrypted TCP connection. As the whole
   thing is to provide a working proof of concept, we need encrypted
   connections right from the beginning. There were thoughts of
   implementing the principle of rings and nodes with unsecure tcp
   connections to get a running sample more quick, but the decision
   was made to implement with secure connections (and all the involved
   overhead) just from the beginning.

   We start with GnuTLS as the crypto library. It is simple to use and
   provides TOFU (trust on first use) secure connection establishment
   which fits exactly into our use case as every ring like structure
   starts as a two point connection and new nodes need out of band
   authentication, too.

   For this three authentication methods are available: PSK
   (pre-shared keys), SRP (password) and Public Keys.  We at least
   should provide the first two and let the users decide which to
   use. A password is simple to communicate out of band for example
   via a phone call, but it may be insecure when people chose too
   simple ones. So we should provide advice in the UI
   acordingly. Advantage: a password is simple to use and people are
   probably used to use it.  Pre shared keys involve steps to generate
   such keys which then need to be communicated out of band. This
   should be a chosable user option too, as it can provide definitely
   secure tokens compared to a self choosen password.

   We start with the more secure PSK DHE_PSK

   Since there is no real destinction between a client and a server in
   a ring of trust network, a node initiating a connection by
   connectioing actively to a remote nodes listening socket is called
   the client, while the node listening and waiting for connections is
   the server in terms of the GnuTLS library implementation.
*/

/* We try to stick to the linux kernel coding style */

/* Maximum pending listen queue length */

#define LISTEN_BACKLOG 12
#define NCOT_CONNECTION_BUFFER_DEFAULT_LENGTH 1024

/* This is for quick distinction between the three possible connection
   types */

enum ncot_connection_type {
	/* control connection used for a deamon */
	NCOT_CONN_CONTROL,
	/* connection is to a neighbour node in a ring, either direction */
	NCOT_CONN_NODE,
	/* connection is the dangling one to listen on for new node
	   requests */
	NCOT_CONN_INCOMING,
	/* connection is used to initiate a communication to another node */
	NCOT_CONN_INITIATE
};

/* We will see if we need this at all. Is for quick determination whats
   up with the conn */

enum ncot_connection_status {
	NCOT_CONN_AVAILABLE,
	NCOT_CONN_CONNECTED,
	NCOT_CONN_LISTEN,
	NCOT_CONN_BOUND,
	NCOT_CONN_INIT
};

/* The conn struct itself. Content taken from one of the examples of
   the GnuTLS package. */

struct ncot_connection;

struct ncot_connection {
	struct ncot_connection *prev;
	struct ncot_connection *next;
	int sd;
	struct sockaddr_in sa_server;
	struct sockaddr_in sa_client;
	struct sockaddr client;
	socklen_t client_len;
	char topbuf[512];
	char buffer[NCOT_CONNECTION_BUFFER_DEFAULT_LENGTH];
	gnutls_session_t session;
	gnutls_anon_server_credentials_t servercred;
	gnutls_anon_client_credentials_t clientcred;
	enum ncot_connection_type type;
	enum ncot_connection_status status;
	int optval;
};

struct ncot_connection *ncot_connection_new();
void ncot_connection_init(struct ncot_connection *connection, enum ncot_connection_type type);
int ncot_connection_listen(struct ncot_context *context, struct ncot_connection *connection, int port);
int ncot_connection_connect(struct ncot_context *context, struct ncot_connection *connection, const char *port, const char *address);
int ncot_connection_accept(struct ncot_context *context, struct ncot_connection *connection);
int ncot_connection_read_data(struct ncot_context *context, struct ncot_connection *connection);
int ncot_connection_write_data(struct ncot_context *context, struct ncot_connection *connection);
void ncot_connection_free(struct ncot_connection **connection);

#endif
