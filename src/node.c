#include "node.h"
#include "log.h"
#include "utlist.h"

struct ncot_node*
ncot_node_new()
{
	struct ncot_node *node;
	node = calloc(1, sizeof(struct ncot_node));
	return node;
}

void
ncot_node_init(struct ncot_node *node) {
	if (node) {
/*		uuid_create(&node->uuid);
		uuid_make(node->uuid, UUID_MAKE_V1); */
	} else {
		NCOT_LOG_WARNING("Invalid node passed to ncot_node_init\n");
	}
}

void
ncot_node_authenticate_peer(struct ncot_node *node, struct ncot_connection *connection)
{
	/* We have the connection accepted and in the connected
	 * state. Lets authenticate the peer. */
	return;
}

void
ncot_node_free(struct ncot_node **pnode) {
	struct ncot_node *node;
	struct ncot_connection *connection;
	if (pnode) {
		node = *pnode;
		if (node) {
/*			if (node->uuid) uuid_destroy(node->uuid);*/
			connection = node->connections;
			while (connection) {
				LL_DELETE(node->connections, connection);
				/*ncot_connection_free(&connection);*/
				connection = node->connections;
			}
			free(node);
			*pnode = NULL;
		} else
			NCOT_LOG_ERROR("Invalid ncot_node\n");
	} else
		NCOT_LOG_ERROR("Invalid argument (*node)\n");
}

