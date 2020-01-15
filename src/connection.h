#ifndef _NCOT_CONNECTION_
#define _NCOT_CONNECTION_

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#elif __unix__
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include <gnutls/gnutls.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <json-c/json.h>

#include "context.h"
#include "packet.h"
#include "node.h"

/** \struct ncot_connection
   A connection is a securely encrypted TCP
   connection. As the whole thing is to provide a working proof of
   concept, we need encrypted connections right from the
   beginning. There were thoughts of implementing the principle of
   rings and nodes with unsecure tcp connections to get a running
   sample more quick, but the decision was made to implement with
   secure connections (and all the involved overhead) just from the
   beginning.

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

/* Function prototype for unknwon host key display and user query */
/* typedef int (*ncot_connection_unknwon_host_query_function)(char *fingerprint, struct ncot_node *node, enum ncot_ssh_keytype type); */
/* maybe later :) */

/** For the proof on concept working sample, and until we have a UI for
 * its input, we use this hard coded PSK */
#define SECRET_KEY "THIS IS THE PRE-SHARED SECRET KEY"

/* We try to stick to the linux kernel coding style */

/** Maximum pending listen queue length */
#define LISTEN_BACKLOG 12

/** Default buffsize of the connection buffer for read/write data */
#define NCOT_CONNECTION_BUFFER_DEFAULT_LENGTH 1024

/** This is for quick distinction between the three possible connection
   types */
enum ncot_connection_type {

	/* control connection used for a deamon */
	NCOT_CONN_CONTROL,

	/* connection is to a neighbour node in a ring, either
	 * direction */
	NCOT_CONN_NODE,

	/* connection is the dangling one to listen on for new node
	 * requests */
	NCOT_CONN_INCOMING,

	/* connection is used to initiate a communication to another
	 * node */
	NCOT_CONN_INITIATE
};

/** We will see if we need this at all. Is for quick determination whats
   up with the conn */
enum ncot_connection_status {
	NCOT_CONN_AVAILABLE,
	NCOT_CONN_CONNECTED,
	NCOT_CONN_ACCEPTED,
	NCOT_CONN_LISTEN,
	NCOT_CONN_BOUND,
	NCOT_CONN_CLOSING,
	NCOT_CONN_INIT
};

/** The default chunksize we start of transmitting with */
#define NCOT_DEFAULT_CHUNKSIZE 2048
#define NCOT_CONN_SSHDIR_LENGTH 2048

struct ncot_connection;
struct ncot_context;
/* struct ssh_server_callbacks_struct; */
/* struct ssh_channel_callbacks_struct; */
/** The conn struct itself. Content taken from one of the examples of
    the GnuTLS package. The list fields prev, next are for the main
    context connections lists only, for a nodes list see next
    section */
struct ncot_connection {
	/** Pointer for connection lists handling */
	struct ncot_connection *prev;
	struct ncot_connection *next;
	/** The node this connection belongs to */
	struct ncot_node *node;
	/** The context this connection belongs to */
	struct ncot_context *context;
	/** This is our socket fd*/
	int sd;
	/** A connections originates either from listening as server
	 * or connectiong as a client. The peer address goes into the
	 * other unsused structure respectively. */
	struct sockaddr_in sa_server;
	struct sockaddr_in sa_client;
	struct sockaddr client;
	socklen_t client_len;
	/** Our buffers for packet handling */
	char buffer[NCOT_CONNECTION_BUFFER_DEFAULT_LENGTH];
	char readbuffer[NCOT_CONNECTION_BUFFER_DEFAULT_LENGTH];
	char *readpointer;
	/** Simple packet queue as utlist */
	struct ncot_packet *packetlist;
	struct ncot_packet *readpacketlist;
	/** Max amount to send in on try. Packages may be split up
	 * which ma be reflected in smaller chunksize. */
	int chunksize;
	/** GnuTLS stuff */
	/* We let this in until we get the libssh implementation work,
	   then remove GnuTLS stuff */
	gnutls_session_t session;
	gnutls_anon_server_credentials_t servercred;
	gnutls_anon_client_credentials_t clientcred;
	gnutls_psk_client_credentials_t pskclientcredentials;
	gnutls_psk_server_credentials_t pskservercredentials;
	int pskclientcredentialsallocated;
	int pskservercredentialsallocated;
	gnutls_datum_t key;
	/** libssh stuff */
	struct ssh_session_struct *sshsession;
	struct ssh_bind_struct *sshbind;
	struct ssh_server_callbacks_struct servercallbacks;
	struct ssh_channel_callbacks_struct channelcallbacks;
	struct ssh_channel_struct *channel;
	int sshlogverbosity;
	char *sshdir;
	int terminate;
	/** Our type */
	enum ncot_connection_type type;
	/** status */
	enum ncot_connection_status status;
	/** setsockopt argument. (Does it need to be here?) */
	int optval;
	int authenticated;
	/** json object needed for storing/loading from config file */
	struct json_object *json;
};

struct ncot_connection_list;
/** A list structure to attach connections objects to nodes. The
 * primary next, prev fields are used for the main context connection
 * lists */
struct ncot_connection_list {
	struct ncot_connection *connection;
	struct ncot_connection_list *next;
	struct ncot_connection_list *prev;
};

struct ncot_connection *ncot_connection_new();
struct ncot_connection* ncot_connection_new_from_json(struct ncot_context *context, struct json_object *jsonobj);
struct ncot_connection_list* ncot_connections_new_from_json(struct ncot_context *context, struct ncot_node *node, struct json_object *jsonobj);
void ncot_connection_init(struct ncot_context *context, struct ncot_node *node, struct ncot_connection *connection, enum ncot_connection_type type);
void ncot_connection_save(struct ncot_connection *connection, struct json_object *parent);
int ncot_connection_listen(struct ncot_context *context, struct ncot_connection *connection, int port);
int ncot_connection_connect(struct ncot_context *context, struct ncot_connection *connection, const char *port, const char *address);
void ncot_connection_close(struct ncot_connection *connection);
int ncot_connection_authenticate_client(struct ncot_connection *connection);
int ncot_connection_authenticate_server(struct ncot_connection *connection);
int ncot_connection_accept(struct ncot_context *context, struct ncot_connection *connection);
int ncot_connection_read_data(struct ncot_context *context, struct ncot_connection *connection);
int ncot_connection_process_data(struct ncot_context *context, struct ncot_connection *connection);
int ncot_connection_write_data(struct ncot_context *context, struct ncot_connection *connection);
int ncot_connection_send(struct ncot_context *context, struct ncot_connection *connection, const char *message, size_t length, enum ncot_packet_type type);
int ncot_connection_send_raw(struct ncot_context *context, struct ncot_connection *connection, const char *message, size_t length);
void ncot_connection_free(struct ncot_connection **connection);

int ncot_control_connection_authenticate(struct ncot_connection *connection);
int ncot_connection_verify_knownhost(struct ncot_context *context, struct ncot_connection *connection);

void ncot_connection_list_free(struct ncot_connection_list **pconnectionlist);
struct ncot_connection_list* ncot_connection_list_new();
char* ncot_connection_get_type_string(struct ncot_connection *connection);
char* ncot_connection_get_status_string(struct ncot_connection *connection);
int ncot_bind_set_control_connection_keyfiles(struct ncot_context *context, struct ssh_bind_struct *sshbind);
int ncot_bind_set_node_keys(struct ssh_bind_struct *sshbind, struct ncot_node *node);
int ncot_connection_open_channel(struct ncot_connection *connection);

static struct ssh_channel_struct* ncot_new_session_channel(ssh_session session, void *userdata);
static int ncot_auth_pubkey(ssh_session session, const char *user, struct ssh_key_struct *pubkey, char signature_state, void *userdata);


#endif
