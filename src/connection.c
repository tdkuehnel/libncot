#include "autoconfig.h"
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "log.h"
#include "connection.h"

struct ncot_connection*
ncot_connection_new()
{
	struct ncot_connection *connection;
	connection = calloc(1, sizeof(struct ncot_connection));
	return connection;
}

void
ncot_connection_init(struct ncot_connection *connection, enum ncot_connection_type type)
{
	if (connection)
	{
		connection->type = type;
		connection->status = NCOT_CONN_INIT;
	}
}

#define SOCKET_ERR(err, s) if(err==-1) {NCOT_LOG_ERROR("%s: %s\n", s, strerror(err));return(1);}
#define SOCKET_NERR(err, s) if(err==-1) {NCOT_LOG_ERROR("%s: %s\n", s, strerror(err));return(-1);}

int
ncot_connection_accept(struct ncot_connection *connection)
{
	if (connection->status == NCOT_CONN_LISTEN) {
		int nsd;
		int err;
		nsd = accept(connection->sd, &connection->client, &connection->client_len);
		SOCKET_NERR(nsd, "ncot_connection_accept: accept()");
		err = close(connection->sd);
		SOCKET_NERR(err, "ncot_connection_accept: close(connection->sd)");
		connection->sd = nsd;
		connection->status = NCOT_CONN_CONNECTED;
		NCOT_LOG_INFO("ncot_connection_accept: connection accepted\n");
	} else {
		NCOT_LOG_ERROR("ncot_connection_accept: connection not in status listen\n");
		return -1;
	}
}

int
ncot_connection_read_data(struct ncot_connection *connection)
{
	int r;
	r = recv(connection->sd, &connection->buffer, NCOT_CONNECTION_BUFFER_DEFAULT_LENGTH, MSG_DONTWAIT);
	NCOT_LOG_INFO("ncot_connection_read_data: %i bytes read\n");
}

int
ncot_connection_write_data(struct ncot_connection *connection)
{
}

int
ncot_connection_listen(struct ncot_connection *connection, int port)
{
	int err;
	if (connection)
	{
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
			setsockopt(connection->sd, SOL_SOCKET, SO_REUSEADDR, (void *) &connection->optval,
				sizeof(int));
			err =
				bind(connection->sd, (struct sockaddr *) &connection->sa_server, sizeof(connection->sa_server));
			SOCKET_ERR(err, "ncot_connection_listen: bind()");
			connection->status = NCOT_CONN_BOUND;
		}

		int ret;
		ret = listen(connection->sd, LISTEN_BACKLOG);
		if (ret == -1) {
			NCOT_LOG_ERROR("Error listening with connection\n");
			return 1;
		}
		else {
			connection->status = NCOT_CONN_LISTEN;
			NCOT_LOG_INFO("connection now listening on port %i\n", port);
			return 0;
		}
	}
}

int
ncot_connection_connect(struct ncot_connection *connection, const char *port, const char *address)
{
	int err;
	if (connection) {
		if (connection->status == NCOT_CONN_CONNECTED) {
			NCOT_LOG_ERROR("Error connection still connected, cant connect again\n");
			return 1;
		}
		if (connection->status == NCOT_CONN_INIT || connection->status == NCOT_CONN_AVAILABLE) {
			connection->sd = socket(AF_INET, SOCK_STREAM, 0);
			SOCKET_ERR(connection->sd, "ncot_connection_connect: socket()");
			memset(&connection->sa_client, '\0', sizeof(connection->sa_client));
			connection->sa_client.sin_family = AF_INET;
			connection->sa_client.sin_port = htons(atoi(port));
			inet_pton(AF_INET, address, &connection->sa_client.sin_addr);

			NCOT_LOG_ERROR("connecting ...\n");
			err = connect(connection->sd, (struct sockaddr *) &connection->sa_client, sizeof(connection->sa_client));
			SOCKET_ERR(err, "ncot_connection_connect: connect()");
			NCOT_LOG_INFO("connect returned %i\n", err);

			connection->status = NCOT_CONN_CONNECTED;
			NCOT_LOG_INFO("connection connected\n");
			gnutls_anon_allocate_client_credentials(&connection->clientcred);
			gnutls_init(&connection->session, GNUTLS_CLIENT);
			/* As we use only that parts of GnuTLS which are not polluted by
			   CA stuff, using NONE here makes sure GnuTLS does not
			   automagically switch in any algorithms we do not want. */
			gnutls_priority_set_direct(connection->session,
						"NONE:+ANON-ECDH:+ANON-DH",
						NULL);
			gnutls_credentials_set(connection->session, GNUTLS_CRD_ANON, connection->clientcred);
			gnutls_transport_set_int(connection->session, connection->sd);
			gnutls_handshake_set_timeout(connection->session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

			return 0;
		}
	} else {
		NCOT_LOG_ERROR("invalid argument ncot_connection\n");
		return 1;
	}
}

void
ncot_connection_close(struct ncot_connection *connection)
{
	if (connection)
	{
		if (connection->status == NCOT_CONN_CONNECTED) {
			gnutls_bye(connection->session, GNUTLS_SHUT_WR);
			close(connection->sd);
			gnutls_deinit(connection->session);
		} else
			NCOT_LOG_WARNING("Trying to close a connection not open\n");
	} else
		NCOT_LOG_ERROR("Invalid argument (*connection)\n");
}

void
ncot_connection_free(struct ncot_connection **pconnection)
{
	struct ncot_connection *connection;
	if (pconnection)
	{
		connection = *pconnection;
		if (connection)
		{
			free(connection);
			*pconnection = NULL;
		} else
			NCOT_LOG_ERROR("Invalid ncot_connection\n");
	} else
		NCOT_LOG_ERROR("Invalid argument (*connection)\n");
}
