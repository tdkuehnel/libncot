#include "autoconfig.h"

#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <libssh/libssh.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#elif __unix__
#include <sys/socket.h>
#include <netdb.h>
#endif

#define DEBUG 0
#include "debug.h"
#include "log.h"
#include "connection.h"
#include "packet.h"
#include "error.h"
#include "utlist.h"

#undef DEBUG
#define DEBUG 0

/* EXPERIMENTAL: only for early testing. TODO: Think of managing ssh keys
 * for all the different nodes involved necessary. */
const char *hostkey = "/home/tdkuehnel/hostkey.rsa";

int
ncot_connection_ensure_hostkey(const char* hostkey)
{
	struct stat buf;
	int i;

	i = stat(hostkey, &buf);
	if (i == 0) {
		/* We have an entry. Check if it is a regular file.*/
		if (buf.st_mode & S_IFREG)
			return NCOT_OK;
		else
			return NCOT_ERROR;
	} else {
		/* No entry, create it. */
		ssh_key key = NULL;
		int rv;

		/* Generate a new  key file */
		rv = ssh_pki_generate(SSH_KEYTYPE_RSA, 1024, &key);
		if (rv != SSH_OK) {
			NCOT_LOG_ERROR("ncot_connection_ensure_hostkey: Failed to generate private key");
			return NCOT_ERROR;
		}

		/* Write it to the path. */
		rv = ssh_pki_export_privkey_file(key, NULL, NULL, NULL, hostkey);
		if (rv != SSH_OK) {
			NCOT_LOG_ERROR("ncot_connection_ensure_hostkey: Failed to write private key file");
			return NCOT_ERROR;
		}
		NCOT_LOG_INFO("New rsa hostkey (1024bit) created in: %s\n", hostkey);
		return NCOT_OK;
	}
}

struct ncot_connection*
ncot_connection_new()
{
	struct ncot_connection *connection;
	connection = calloc(1, sizeof(struct ncot_connection));
	if (connection) {
		connection->chunksize = NCOT_DEFAULT_CHUNKSIZE;
		connection->readpointer = connection->readbuffer;
		connection->sshbind = ssh_bind_new();
		ncot_connection_ensure_hostkey(hostkey);
		ssh_bind_options_set(connection->sshbind, SSH_BIND_OPTIONS_RSAKEY, hostkey);

	}
	return connection;
}

void
ncot_connection_init(struct ncot_connection *connection, enum ncot_connection_type type)
{
	if (connection)
	{
		connection->type = type;
		connection->status = NCOT_CONN_INIT;
		connection->pskclientcredentialsallocated = 0;
		connection->pskservercredentialsallocated = 0;
	}
}

#undef DEBUG
#define DEBUG 1
void
ncot_connection_free(struct ncot_connection **pconnection)
{
	struct ncot_connection *connection;
	struct ncot_packet *packet;
	struct ncot_packet *deletepacket;
	if (pconnection)
	{
		connection = *pconnection;
		if (connection)
		{
			packet = connection->readpacketlist;
			NCOT_DEBUG("ncot_connection_free: 1\n");
			while (packet) {
				/*ncot_packet_print(packet);*/
				NCOT_DEBUG("ncot_connection_free: deleting packet\n");
				deletepacket = packet;
				packet = packet->next;
				LL_DELETE(connection->readpacketlist, deletepacket);
				ncot_packet_free(&deletepacket);
			}
			if (connection->sshsession) ssh_free(connection->sshsession);
			if (connection->sshbind) ssh_bind_free(connection->sshbind);
			NCOT_DEBUG("ncot_connection_free: closing connection\n");
			if (connection->status == NCOT_CONN_CONNECTED) ncot_connection_close(connection);
			NCOT_DEBUG("ncot_connection_free: freeing connection\n");

			free(connection);
			*pconnection = NULL;
		} else
			NCOT_LOG_ERROR("Invalid ncot_connection\n");
	} else
		NCOT_LOG_ERROR("Invalid argument (*connection)\n");
}

char*
ncot_connection_get_type_string(struct ncot_connection *connection)
{
	char *type;
	if (!connection) return "<empty>";
	switch (connection->type) {
	case NCOT_CONN_CONTROL:
		type = "CONTROL";
		break;
	case NCOT_CONN_NODE:
		type = "NODE";
		break;
	case NCOT_CONN_INCOMING:
		type = "INCOMING";
		break;
	case NCOT_CONN_INITIATE:
		type = "INITIATE";
		break;
	default:
		type = "<unknwon>";
	}
	return type;
}

char*
ncot_connection_get_status_string(struct ncot_connection *connection)
{
	char *status;
	if (!connection) return "<empty>";
	switch (connection->status) {
	case NCOT_CONN_AVAILABLE:
		status = "AVAILABLE";
		break;
	case NCOT_CONN_CONNECTED:
		status = "CONNECTED";
		break;
	case NCOT_CONN_LISTEN:
		status = "LISTEN";
		break;
	case NCOT_CONN_BOUND:
		status = "BOUND";
		break;
	case NCOT_CONN_INIT:
		status = "INIT";
		break;
	default:
		status = "<unknown>";
	}
	return status;
}

struct ncot_connection*
ncot_connection_new_from_json(struct json_object *jsonobj)
{
}

struct ncot_connection_list*
ncot_connections_new_from_json(struct json_object *jsonobj)
{
	struct ncot_connection_list *connectionlist = NULL;
	struct ncot_connection_list *returnlist = NULL;
	struct json_object *jsonnode;
	int numconnections;
	int i;
	numconnections = json_object_array_length(jsonobj);
	for (i=0; i<numconnections; i++) {
		jsonnode = json_object_array_get_idx(jsonobj, i);
		connectionlist = ncot_connection_list_new();
		RETURN_ZERO_IF_NULL(connectionlist, "ncot_connection_new_from_json: out of memory");
		connectionlist->connection = ncot_connection_new();
		if (!connectionlist->connection) {
			NCOT_LOG_ERROR("ncot_connection_new_from_json: out of memory");
			free(connectionlist);
			return NULL;
		}
		ncot_connection_init(connectionlist->connection, NCOT_CONN_NODE);
		DL_APPEND(returnlist, connectionlist);
	}
	return returnlist;

}

/* Saving a connection makes sense only when it has information about
 * a peer. Do we really need to store own ip-address, port number ?
 * Don't think so at the moment, but who knows.*/
void
ncot_connection_save(struct ncot_connection *connection, struct json_object *parent)
{
	int ret;
	char *string =  NULL;
	struct json_object *json;
	struct sockaddr_in *sockaddr;

	sockaddr = (struct sockaddr_in *)&connection->client;
	json = json_object_new_string(inet_ntoa(sockaddr->sin_addr));
	json_object_object_add_ex(parent, "Host", json, JSON_C_OBJECT_KEY_IS_CONSTANT);

	json = json_object_new_int(ntohs(sockaddr->sin_port));
	json_object_object_add_ex(parent, "Port", json, JSON_C_OBJECT_KEY_IS_CONSTANT);

}

#ifdef DEBUG
#undef DEBUG
#define DEBUG 0
#endif
/* This is a function that, yes, copies a message, queues it and takes
 * the necessary steps to send it to the peer */
int
ncot_connection_send(struct ncot_context *context, struct ncot_connection *connection, const char *message, size_t length, enum ncot_packet_type type)
{
	struct ncot_packet *packet;
	NCOT_DEBUG("ncot_connections_send: sending message with %i bytes\n", length);
	packet = ncot_packet_new_with_message(message, length, type);
	RETURN_ZERO_IF_NULL(packet, "ncot_connection_send: Out of memory");
	LL_APPEND(connection->packetlist, packet);
	ncot_context_enqueue_connection_writing(context, connection);
	return length;
}

int
ncot_connection_send_raw(struct ncot_context *context, struct ncot_connection *connection, const char *message, size_t length)
{
	struct ncot_packet *packet;
	NCOT_DEBUG("ncot_connections_send_raw: sending raw %i bytes\n", length);
	packet = ncot_packet_new_with_data(message, length);
	RETURN_ZERO_IF_NULL(packet, "ncot_connection_send_raw: Out of memory");
	LL_APPEND(connection->packetlist, packet);
	ncot_context_enqueue_connection_writing(context, connection);
	return length;
}

/* GnuTLS stuff starts here */

// GnuTLS calls this function to get the pre-shared key. The client will tell
// the server its username, and GnuTLS will give us that username. We have to
// return the key that we share with that client. We set this callback with
// gnutls_psk_set_server_credentials_function().
int psk_creds(gnutls_session_t session, const char *username, gnutls_datum_t *key)
{
	// For this example, we ignore the username and return the same key every
	// time. In a real application, you would look up the key for the username
	// and return that. If the username does not exist, return a negative
	// number (see the manual).
	key->size = strlen(SECRET_KEY);
#ifdef _WIN32
	key->data = malloc(key->size);
#else
	key->data = gnutls_malloc(key->size);
#endif
	if (key->data == NULL) {
		return -1;
	}
	memcpy(key->data, SECRET_KEY, key->size);
	return 0;
}


int
ncot_connection_authenticate_client(struct ncot_connection *connection)
{
	int r;
	if (!connection) return NCOT_ERROR;
	if (!connection->sshsession) return NCOT_ERROR;
	r = ssh_handle_key_exchange(connection->sshsession);
	if (!r == SSH_OK) {
		NCOT_LOG_ERROR("ncot_connection_authenticate_client: error during key exchange\n");
		return NCOT_ERROR;
	}
	NCOT_LOG_INFO("ncot_connection_authenticate_client: after key exchange (OK)\n");
	return SSH_OK;
}

int
ncot_connection_authenticate_client_gnutls(struct ncot_connection *connection)
{
	int err;
	int res;
	err = gnutls_init(&connection->session, GNUTLS_SERVER);
	GNUTLS_ERROR(err, "Error during gnutls_init()");

	err = gnutls_psk_allocate_server_credentials(&connection->pskservercredentials);
	GNUTLS_ERROR(err, "Error during gnutls_psk_allocate_server_credentials()");
	connection->pskservercredentialsallocated = 1;

	gnutls_psk_set_server_credentials_function(connection->pskservercredentials, psk_creds);

	res = gnutls_credentials_set(connection->session, GNUTLS_CRD_PSK, connection->pskservercredentials);
	GNUTLS_ERROR(res, "Error during gnutls_credentials_set()");

	res = gnutls_priority_set_direct(connection->session,	"SECURE128:-VERS-SSL3.0:-VERS-TLS1.0:-ARCFOUR-128:+PSK:+DHE-PSK", NULL);
	GNUTLS_ERROR(res, "Error during gnutls_priority_set_direct()");

	gnutls_transport_set_int(connection->session, connection->sd);

	NCOT_DEBUG("Gnutls stuff setup, lets shake hands\n");
	do {
		NCOT_DEBUG("Gnutls_handshake accept iteration\n");
		res = gnutls_handshake(connection->session);
		NCOT_DEBUG("Gnutls_handshake returned %i \n", res);
	} while ( res != 0 && !gnutls_error_is_fatal(res) );
	if (gnutls_error_is_fatal(res)) {
		GNUTLS_ERROR(res, "Fatal error during TLS handshake.");
	}
	NCOT_DEBUG("ncot_connection_authenticate_client: Gnutls handshake complete\n");
	NCOT_LOG_INFO("Gnutls handshake complete\n");
	/*gnutls_transport_set_int(connection->session, connection->sd);*/
	connection->authenticated = 1;
	return 0;
}

int
ncot_connection_accept(struct ncot_context *context, struct ncot_connection *connection)
{
	int r;
	if (connection->status != NCOT_CONN_LISTEN) RETURN_FAIL("ncot_connection_accept: connection not in listening state");
	if (!connection->sshsession) connection->sshsession = ssh_new();
        r = ssh_bind_accept(connection->sshbind, connection->sshsession);
	if (!r == SSH_OK) {
		NCOT_LOG_ERROR("ncot_connection_accept: ssh_bind_accept unsuccesful\n");
		return NCOT_ERROR;
	}
	connection->status = NCOT_CONN_CONNECTED;
	ncot_context_dequeue_connection_listen(context, connection);
	ncot_context_enqueue_connection_connected(context, connection);
	NCOT_LOG_VERBOSE("ncot_connection_accept: connection accepted\n");
	return 0;
}

int
ncot_connection_accept_bare(struct ncot_context *context, struct ncot_connection *connection)
{
	if (connection->status != NCOT_CONN_LISTEN) RETURN_FAIL("ncot_connection_accept: connection not in listening state");
	int nsd;
	int err;
	connection->client_len = sizeof(struct sockaddr);
	nsd = accept(connection->sd, &connection->client, &connection->client_len);
	SOCKET_NERR(nsd, "ncot_connection_accept: accept()");
	err = close(connection->sd);
	SOCKET_NERR(err, "ncot_connection_accept: close(connection->sd)");
	connection->sd = nsd;
	struct sockaddr_in *addr_in = (struct sockaddr_in *)&connection->client;
	switch(connection->client.sa_family) {
	case AF_INET: {
		NCOT_LOG_INFO("peer ip4 address: %s\n", inet_ntoa(addr_in->sin_addr));
		break;
	}
	case AF_INET6: {
		NCOT_LOG_INFO("peer ip6 address: %s\n", inet_ntoa(addr_in->sin_addr));
		break;
	}
	default:
		NCOT_LOG_INFO("peer address: %s\n", inet_ntoa(addr_in->sin_addr));
	}
	connection->status = NCOT_CONN_CONNECTED;
	ncot_context_dequeue_connection_listen(context, connection);
	ncot_context_enqueue_connection_connected(context, connection);
	NCOT_LOG_VERBOSE("ncot_connection_accept: connection accepted\n");
	return 0;
}

int
ncot_connection_read_data(struct ncot_context *context, struct ncot_connection *connection)
{
	int r;
	int read_max;
	read_max = NCOT_CONNECTION_BUFFER_DEFAULT_LENGTH - (connection->readpointer - connection->readbuffer);
	if (read_max <= 0) {
		NCOT_LOG_WARNING("ncot_connection_read_data: read buffer full\n");
		return 0;
	}
#ifdef _WIN32
	u_long iMode = 1;
	ioctlsocket(connection->sd, FIONBIO, &iMode);
	r = recv(connection->sd, (char*)connection->readpointer, read_max, 0);
#else
	r = recv(connection->sd, connection->readpointer, read_max, MSG_DONTWAIT);
#endif
#ifdef _WIN32
	iMode = 0;
	ioctlsocket(connection->sd, FIONBIO, &iMode);
#endif
	SOCKET_NERR(r, "ncot_connection_read_data: error recv:");
	connection->readpointer += r;
	*connection->readpointer = 0;
	NCOT_DEBUG("ncot_connection_read_data: %i bytes read\n", r);
	NCOT_DEBUG_HEX("ncot_connection_read_data: data read is", connection->readbuffer, 64);
	return r;
}

int
ncot_connection_process_data(struct ncot_context *context, struct ncot_connection *connection)
{
	int buffread; /* amount of read in data */
	int packetdatalength;
	int packetlength;
	struct ncot_packet_data *packetdata;
	struct ncot_packet *packet;

	buffread = connection->readpointer - connection->readbuffer;
	/* We need at least the size of an empty (command only) packet */
	if (buffread < NCOT_PACKET_VALID_MIN_LENGTH) {
		NCOT_DEBUG("ncot_connection_process_data: to few new bytes to process data: %i\n", buffread);
		return 0;
	}
	/* Assume a valid packet starts buffer beginning */
	packetdata = (struct ncot_packet_data*)connection->readbuffer;
	/* We have at least the packet header with length field */
	packetdatalength = ntohs(packetdata->length);
	packetlength = packetdatalength + NCOT_PACKET_DATA_HEADER_LENGTH;
	NCOT_DEBUG("ncot_connection_process_data: packetlength: %i, packetdatalength: %i, buffread: %i\n", packetlength, packetdatalength, buffread);
	/* When we have a complete packet, store it away */
	if (buffread >= packetlength) {
		NCOT_DEBUG("ncot_connection_process_data: processing packet data with length %i\n", packetlength);

		packet = ncot_packet_new_with_data(connection->readbuffer, packetdatalength + NCOT_PACKET_DATA_HEADER_LENGTH);
		LL_APPEND(connection->readpacketlist, packet);
		/* Copy the rest of the read in bytes to the beginning
		 * of the readbuffer (part of or complete packet) */
		memmove(connection->readbuffer, connection->readbuffer + packetlength, connection->readpointer - (connection->readbuffer + packetlength));
		connection->readpointer -= packetlength;
		return 1; /* One packet taken out of buffer */
	}
	NCOT_DEBUG("ncot_connection_process_data: no complete packet in buffer, bytes: %i\n", buffread);
	return 0;
}

int
ncot_connection_write_data(struct ncot_context *context, struct ncot_connection *connection)
{
	/* We need to check how much data there still is to write,
	 * write some amount and then check if we are done with
	 * writing to take the connection out of the writing list */
	ssize_t amount;
	struct ncot_packet *packet;
	struct ncot_packet_data *pointer;
	if (!connection->packetlist) {
		ncot_context_dequeue_connection_writing(context, connection);
		NCOT_DEBUG("ncot_connection_write_data: No more packets in queue\n");
		return 0;
	}
	packet = connection->packetlist;
	NCOT_DEBUG("ncot_connection_write_data: packet->length is %i bytes\n", packet->length);
	amount = packet->length - packet->index;
	NCOT_DEBUG("ncot_connection_write_data: amount is %i bytes\n", amount);
	if (amount == 0) {
		LL_DELETE(connection->packetlist, packet);
		/* We deliberately return here, as the pselect loop
		 * sends us straight back so that with no more packet
		 * to send at all we got removed from the writing
		 * list */
		/* We need somehow reuse our packets or all this
		 * allocating/deallocating of memory may led to
		 * problems ? */
		NCOT_DEBUG("ncot_connection_write_data: taking empty packet out of packetlist and freeing packet\n");
		ncot_packet_free(&packet);
		return 0;
	}
	if (amount > connection->chunksize) amount = connection->chunksize;
	NCOT_DEBUG("ncot_connection_write_data: connection->chunksize is %i bytes\n", connection->chunksize);
	pointer = packet->data + packet->index;
	NCOT_DEBUG("ncot_connection_write_data: going to send %i bytes\n", amount);
#ifdef _WIN32
	u_long iMode = 1;
	ioctlsocket(connection->sd, FIONBIO, &iMode);
	amount = send(connection->sd, (char*)pointer, amount, 0);
#else
	amount = send(connection->sd, pointer, amount, MSG_DONTWAIT);
#endif
#ifdef _WIN32
	iMode = 0;
	ioctlsocket(connection->sd, FIONBIO, &iMode);
#endif
	NCOT_DEBUG("ncot_connection_write_data: %i bytes send by call\n", amount);
	if (amount == -1) {
		/* We need to check for the reason why this may
		fail. If it would block, we need somehow take our
		connection out of the writing list for some time. Here
		comes the timeout value from the pselect call in
		handy. We could enable timed out pselect only when we
		have blocking writing i/o and a context->waiting list
		where we got back in from with our blocking connection
		when some amount of time has passed. For now we ignore
		errors at all ! FIXME */
		return 0;
	}
	/* We have sent some data.*/
	packet->index += amount;
	NCOT_DEBUG("ncot_connection_write_data: %i bytes send.\n", amount);
	return amount;
	/* TODO: We need to check for EMSGSIZE and split the chunksize accordingly. */
}

const char *ncot_ssh_banner = "* ncot ssh connection banner *";

int
ncot_connection_listen(struct ncot_context *context, struct ncot_connection *connection, int port)
{
	int r;
	if (!connection) ERROR_MESSAGE_RETURN("ncot_connection_listen: Invalid argument: connection");
	if (!connection->sshbind) ERROR_MESSAGE_RETURN("ncot_connection_listen: Invalid argument: connection->sshbind");
	if (connection->status == NCOT_CONN_CONNECTED)
	{
		NCOT_LOG_ERROR("ncot_connection_listen: connection still connected, cant listen\n");
		return 1;
	}
	ssh_bind_options_set(connection->sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
	ssh_bind_options_set(connection->sshbind, SSH_BIND_OPTIONS_BANNER, &ncot_ssh_banner);
	NCOT_LOG_INFO("ncot_connection_listen: trying to listen on port %i\n", port);
	r = ssh_bind_listen(connection->sshbind);
	if (r != SSH_OK) {
		NCOT_LOG_ERROR("ncot_connection_listen: ssh_bind_listen failed: %s\n", ssh_get_error(connection->sshbind));
		return NCOT_ERROR;
	}
	connection->status = NCOT_CONN_LISTEN;
	ncot_context_enqueue_connection_listen(context, connection);
	NCOT_LOG_INFO("ncot_connection_listen: connection now listening on port %i\n", port);
	return 0;

}

int
ncot_connection_listen_bare(struct ncot_context *context, struct ncot_connection *connection, int port)
{
	int err;
	if (!connection) ERROR_MESSAGE_RETURN("ncot_connection_listen: Invalid argument: connection");
	if (connection->status == NCOT_CONN_CONNECTED)
	{
		NCOT_LOG_ERROR("Error connection still connected, cant listen\n");
		return 1;
	}
	if (connection->status == NCOT_CONN_INIT)
	{
		connection->sd = socket(AF_INET, SOCK_STREAM, 0);
		SOCKET_ERR(connection->sd, "ncot_connection_listen: socket()");
		memset(&connection->sa_server, '\0', sizeof(connection->sa_server));
		connection->sa_server.sin_family = AF_INET;
		connection->sa_server.sin_addr.s_addr = INADDR_ANY;
		connection->sa_server.sin_port = htons(port); /* Server Port number */
		setsockopt(connection->sd, SOL_SOCKET, SO_REUSEADDR, (void *) &connection->optval, sizeof(int));
		err = bind(connection->sd, (struct sockaddr *) &connection->sa_server, sizeof(connection->sa_server));
		SOCKET_ERR(err, "ncot_connection_listen: bind()");
		connection->status = NCOT_CONN_BOUND;
	}

	int ret;
	ret = listen(connection->sd, LISTEN_BACKLOG);
	SOCKET_ERR(ret, "Error listening with connection\n");
	connection->status = NCOT_CONN_LISTEN;
	ncot_context_enqueue_connection_listen(context, connection);
	NCOT_LOG_INFO("ncot_connection_listen: connection now listening on port %i\n", port);
	return 0;
}

int
ncot_connection_authenticate_server(struct ncot_connection *connection)
{
	return ssh_userauth_none(connection->sshsession, NULL);
}

int
ncot_connection_authenticate_server_gnutls(struct ncot_connection *connection)
{
	int err;
	int res;
	err = gnutls_init(&connection->session, GNUTLS_CLIENT);
	GNUTLS_ERROR(err, "Error during gnutls_init()");

	err = gnutls_psk_allocate_client_credentials(&connection->pskclientcredentials);
	GNUTLS_ERROR(err, "Error during gnutls_psk_allocate_client_credentials()");
	connection->pskclientcredentialsallocated = 1;
	connection->key.size = strlen(SECRET_KEY);
	connection->key.data = malloc(connection->key.size);
	memcpy(connection->key.data, SECRET_KEY, connection->key.size);
	res = gnutls_psk_set_client_credentials(connection->pskclientcredentials, "Alice", &connection->key, GNUTLS_PSK_KEY_RAW);
	memset(connection->key.data, 0, connection->key.size);
	free(connection->key.data);
	connection->key.data = NULL;
	connection->key.size = 0;
	GNUTLS_ERROR(res, "Error during gnutls_psk_set_client_credentials()");

	res = gnutls_credentials_set(connection->session, GNUTLS_CRD_PSK, connection->pskclientcredentials);
	GNUTLS_ERROR(res, "Error during gnutls_credentials_set()");

	/* As we use only the parts of GnuTLS which are not
	   polluted by CA stuff, using NONE here makes sure
	   GnuTLS does not automagically switch in any
	   algorithms we do not want. */
/*		gnutls_priority_set_direct(connection->session,	"NONE:+PSK-DH",	NULL);*/
	res = gnutls_priority_set_direct(connection->session,	"SECURE128:-VERS-SSL3.0:-VERS-TLS1.0:-ARCFOUR-128:+PSK:+DHE-PSK", NULL);
	GNUTLS_ERROR(res, "Error during gnutls_priority_set_direct()");

	gnutls_transport_set_int(connection->session, connection->sd);

	NCOT_DEBUG("Gnutls stuff setup, lets shake hands\n");
	do {
		NCOT_DEBUG("Gnutls_handshake connect iteration\n");
		res = gnutls_handshake(connection->session);
		NCOT_DEBUG("Gnutls_handshake returned %i \n", res);
	} while ( res != 0 && !gnutls_error_is_fatal(res) );
	if (gnutls_error_is_fatal(res)) {
		GNUTLS_ERROR(res, "Fatal error during TLS handshake.");
	}
	NCOT_DEBUG("GnuTLS handshake complete\n");
	/*gnutls_transport_set_int(connection->session, connection->sd);*/
	connection->authenticated = 1;
	return 0;
}

int
ncot_connection_connect(struct ncot_context *context, struct ncot_connection *connection, const char *port, const char *address)
{
	if (!context) return NCOT_ERROR;
	if (!connection) return NCOT_ERROR;
	if (!connection->sshsession) connection->sshsession = ssh_new();
	if (ssh_options_set(connection->sshsession, SSH_OPTIONS_HOST, address) < 0) return NCOT_ERROR;
	if (ssh_options_set(connection->sshsession, SSH_OPTIONS_PORT_STR, port) < 0) return NCOT_ERROR;
	/* last parameter of the following call can be our ssh config file name */
	ssh_options_parse_config(connection->sshsession, NULL);
	NCOT_LOG_INFO("ncot_connection_connect: trying to connect to %s %s\n", address, port);
	if (ssh_connect(connection->sshsession)) {
		NCOT_LOG_ERROR("ncot_connection_connect: Connection failed : %s\n", ssh_get_error(connection->sshsession));
		ssh_disconnect(connection->sshsession);
		return NCOT_ERROR;
	}
	connection->status = NCOT_CONN_CONNECTED;
	ncot_context_enqueue_connection_connected(context, connection);
	NCOT_LOG_INFO("ncot_connection_connect: Connection connected\n");
	return NCOT_OK;
}

int
ncot_connection_connect_bare(struct ncot_context *context, struct ncot_connection *connection, const char *port, const char *address)
{
	int err;
	int res;
	struct addrinfo hints;
	struct addrinfo *results;
	struct addrinfo *result;
	struct sockaddr_in *sockaddr;
	if (!connection) ERROR_MESSAGE_RETURN("ncot_connection_connect: Invalid argument: connection");
	if (connection->status == NCOT_CONN_CONNECTED) ERROR_MESSAGE_RETURN("ncot_connection_connect - ERROR: connection still connected, cant connect again\n");
	if (connection->status == NCOT_CONN_INIT || connection->status == NCOT_CONN_AVAILABLE) {
		memset(&hints, '\0', sizeof(struct addrinfo));
		hints.ai_family = AF_INET; /* ip4 for the moment only to simplify*/
		hints.ai_socktype = SOCK_STREAM;
#ifdef _WIN32
		hints.ai_flags = AI_NUMERICHOST; /* for simplicity of this proof of concept */
#else
		hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_CANONNAME ; /* for simplicity of this proof of concept */
#endif
		res = getaddrinfo(address, port, &hints, &results);
		if (res != 0) {
			NCOT_LOG_ERROR("ncot_connection_connect: error in getaddrinfo - %s\n", gai_strerror(res));
			return -1;
		}
		NCOT_DEBUG("ncot_connection_connect: connecting ...\n");
		for (result = results; result != NULL; result = result->ai_next) {
			connection->sd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
			if (connection->sd == -1)
				continue;
			if (connect(connection->sd, result->ai_addr, result->ai_addrlen) != -1)
				break;
			close(connection->sd);
		}
		freeaddrinfo(results);
		RETURN_FAIL_IF_NULL(result, "ncot_connection_connect: not successful (after getaddrinfo iteration)");
		sockaddr = (struct sockaddr_in *)&connection->client;
		res = inet_aton(address, &sockaddr->sin_addr);
		sockaddr->sin_port = htons(atoi(port));
		NCOT_DEBUG("ncot_connection_connect: connect successful (after getaddrinfo iteration) %i\n", err);
		connection->status = NCOT_CONN_CONNECTED;
		ncot_context_enqueue_connection_connected(context, connection);
		NCOT_LOG_INFO("ncot_connection_connect: connection connected\n");
		return 0;
	}
}

void
ncot_connection_close(struct ncot_connection *connection)
{
	if (!connection) RETURN_ERROR_STR("ncot_connection_close: bad connection parameter.");
	if (!connection->sshsession) RETURN_ERROR_STR("ncot_connection_close: bad connection->session parameter.");
	if (connection->status != NCOT_CONN_CONNECTED) RETURN_WARNING_STR("ncot_connection_close: Trying to close a connection not open.");
	ssh_disconnect(connection->sshsession);
	connection->status == NCOT_CONN_INIT;
	NCOT_LOG_INFO("ncot_connection_close: closing a connection.");
}



#ifdef DEBUG
#undef DEBUG
#endif
#define DEBUG 1
void
ncot_connection_close_bare(struct ncot_connection *connection)
{
	if (connection)
	{
		NCOT_DEBUG("ncot_connection_close: 1\n");
		if (connection->status == NCOT_CONN_CONNECTED) {
			NCOT_DEBUG("ncot_connection_close: 2\n");
			if (connection->session) gnutls_bye(connection->session, GNUTLS_SHUT_WR);
			NCOT_DEBUG("ncot_connection_close: 3\n");
			if (connection->session) gnutls_deinit(connection->session);
			NCOT_DEBUG("ncot_connection_close: 4\n");
			/* We have our pskclientcredentials plain in the struct (FIXME?)
			   gnutls_psk_free_client_credentials(connection->pskclientcredentials);*/
			if (connection->pskclientcredentialsallocated)
				gnutls_psk_free_client_credentials(connection->pskclientcredentials);
			if (connection->pskservercredentialsallocated)
				gnutls_psk_free_server_credentials(connection->pskservercredentials);
			NCOT_DEBUG("ncot_connection_close: 5\n");
			close(connection->sd);
			NCOT_DEBUG("ncot_connection_close: 6\n");
			connection->status == NCOT_CONN_INIT;
			NCOT_LOG_INFO("closing a connection\n");
		} else
			NCOT_LOG_WARNING("Trying to close a connection not open\n");
	} else
		NCOT_LOG_ERROR("Invalid argument (*connection)\n");
}


/** Every connection belongs to exactly one connection list. So when
 * we make sure that a connection list is responsible for releasing
 * its connection, it should work. Don't free a connection
 * otherwise. */
void
ncot_connection_list_free(struct ncot_connection_list **pconnectionlist)
{
	struct ncot_connection_list *connectionlist;
	if (pconnectionlist)
	{
		connectionlist = *pconnectionlist;
		if (connectionlist)
		{
			if (connectionlist->connection) {
				ncot_connection_free(&connectionlist->connection);
			} else {
				NCOT_LOG_WARNING("ncot_connection_list_free: connection empty, no connection to free (should not happen)\n");
			}
			free(connectionlist);
			*pconnectionlist = NULL;
		}
	}
}

struct ncot_connection_list*
ncot_connection_list_new()
{
	struct ncot_connection_list *connectionlist;
	connectionlist = calloc(1, sizeof(struct ncot_connection_list));
	return connectionlist;
}

