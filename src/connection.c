#include "autoconfig.h"
#include <unistd.h>
#include "log.h"
#include "connection.h"

struct ncot_connection *ncot_connection_new()
{
  struct ncot_connection *connection;
  connection = calloc(1, sizeof(struct ncot_connection));
  return connection;
}

void ncot_connection_init(struct ncot_connection *connection, enum ncot_connection_type type)
{
  if (connection)
    {
      connection->type = type;
      connection->status = NCOT_CONN_INIT;
    }
}

void ncot_connection_listen(struct ncot_connection *connection, int port)
{
  if (connection)
    {
      listen(connection->fd, LISTEN_BACKLOG);
    }
}

void ncot_connection_close(struct ncot_connection *connection)
{
  if (connection)
    {
      if (connection->status == NCOT_CONN_CONNECTED) {
	gnutls_bye(connection->session, GNUTLS_SHUT_WR);
	close(connection->fd);
	gnutls_deinit(connection->session);    
      } else 
	NCOT_LOG_WARNING("Trying to close a connection not open\n");
    } else
    NCOT_LOG_ERROR("Invalid argument (*connection)\n"); 
}

void ncot_connection_free(struct ncot_connection *connection)
{
  if (connection)
    {
      free(connection);
    } else 
    NCOT_LOG_ERROR("Invalid argument (*connection)\n");
}
