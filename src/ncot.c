#include <uuid.h>

#include "autoconfig.h"
#include "ncot.h"
#include "log.h"

ncot_connection_t *ncot_connection_new()
{
  ncot_connection_t *connection;
  connection = calloc(1, sizeof(ncot_connection_t));
  return connection;
}

void ncot_connection_init(ncot_connection_t *connection, ncot_connection_type_t type)
{
  if (connection)
    {
      connection->type = type;
      connection->status = NCOT_CONN_INIT;
    }
}

void ncot_connection_listen(ncot_connection_t *connection, int port)
{
  if (connection)
    {
      listen(connection->fd, LISTEN_BACKLOG);
    }
}

void ncot_connection_close(ncot_connection_t *connection)
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

void ncot_connection_free(ncot_connection_t *connection)
{
  if (connection)
    {
      free(connection);
    } else 
    NCOT_LOG_ERROR("Invalid argument (*connection)\n");
}

ncot_node_t *ncot_node_new()
{
  ncot_node_t *node;
  node = calloc(1, sizeof(ncot_node_t));
  return node;
}

void ncot_node_init(ncot_node_t *node) {
  if (node) {
    uuid_create(&node->uuid);
    uuid_make(node->uuid, UUID_MAKE_V1);    
  } else {
    NCOT_LOG_WARNING("Invalid node passed to ncot_node_init\n");
  }
}

void ncot_node_free(ncot_node_t **pnode) {
  ncot_node_t *node;
  if (pnode) {
    node = *pnode;
    if (node) {
      if (node->uuid) uuid_destroy(node->uuid);
      free(node);
      *pnode = NULL;
    } else
      NCOT_LOG_ERROR("Invalid ncot_node\n");
  } else 
    NCOT_LOG_ERROR("Invalid argument (*node)\n");
}


ncot_identity_t *ncot_identity_new()
{
  ncot_identity_t *identity;
  identity = calloc(1, sizeof(ncot_identity_t));
  return identity;
}

void ncot_identity_init(ncot_identity_t *identity) {
  if (identity) {
    uuid_create(&identity->uuid);
    uuid_make(identity->uuid, UUID_MAKE_V1);    
  } else {
    NCOT_LOG_WARNING("Invalid identity passed to ncot_identity_init\n");
  }
}

void ncot_identity_free(ncot_identity_t **pidentity) {
  ncot_identity_t *identity;
  if (pidentity) {
    identity = *pidentity;
    if (identity) {
      if (identity->uuid) uuid_destroy(identity->uuid);
      free(identity);
      *pidentity = NULL;
    } else
      NCOT_LOG_ERROR("Invalid ncot_identity\n");
  } else 
    NCOT_LOG_ERROR("Invalid argument (*identity)\n");
}



void ncot_init()
{
  ncot_log_init(NCOT_LOG_LEVEL_WARNING);
  NCOT_LOG_INFO("%s\n", PACKAGE_STRING);
  gnutls_global_init();

}

void ncot_done()
{
  gnutls_global_deinit();
  ncot_log_done();
}
