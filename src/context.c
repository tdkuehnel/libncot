#define DEBUG 0
#include "debug.h"
#include "context.h"
#include "utlist.h"
#include "node.h"

struct ncot_context*
ncot_context_new()
{
	struct ncot_context *context;
	context = calloc(1, sizeof(struct ncot_context));
	return context;
}

void
ncot_context_init(struct ncot_context *context)
{
	if (context) {
		/*    context->config = ncot_config_new(); */
		context->arguments = calloc(1, sizeof(struct ncot_arguments));
		context->globalnodelist = NULL;
		context->controlconnection = ncot_connection_new();
		ncot_connection_init(context->controlconnection, NCOT_CONN_CONTROL);
	} else {
		NCOT_LOG_WARNING("Invalid context passed to ncot_context_init\n");
	}
}

void
ncot_context_abort_connection_io(struct ncot_context *context)
{
	struct ncot_connection *connection;
	connection = context->connections_listen;
	while (connection) {
		LL_DELETE(context->connections_listen, connection);
		connection = context->connections_listen;
	}
	connection = context->connections_writing;
	while (connection) {
		LL_DELETE(context->connections_writing, connection);
		connection = context->connections_writing;
	}
	connection = context->connections_connected;
	while (connection) {
		LL_DELETE(context->connections_connected, connection);
		connection = context->connections_connected;
	}
	connection = context->connections_closed;
	while (connection) {
		LL_DELETE(context->connections_closed, connection);
		connection = context->connections_closed;
	}

}

void
ncot_context_nodes_free(struct ncot_context *context)
{
	struct ncot_node *node;
	node = context->globalnodelist;
	while (node) {
		LL_DELETE(context->globalnodelist, node);
		ncot_node_free(&node);
		node = context->globalnodelist;
	}
}

#ifdef DEBUG
#undef DEBUG
#endif
#define DEBUG 0
void
ncot_context_free(struct ncot_context **pcontext) {
	struct ncot_context *context;
	if (pcontext) {
		context = *pcontext;
		if (context) {
			context = *pcontext;
			NCOT_DEBUG("ncot_context_free: 1 freeing context at 0x%x\n", context);
			/*      if (context->config) free(context->config); */
			ncot_context_abort_connection_io(context);
			NCOT_DEBUG("ncot_context_free: 2 freeing context at 0x%x\n", context);
			ncot_context_nodes_free(context);
			NCOT_DEBUG("ncot_context_free: 3 freeing context at 0x%x\n", context);
			if (context->controlconnection) ncot_connection_free(&context->controlconnection);
			NCOT_DEBUG("ncot_context_free: 4 freeing context at 0x%x\n", context);
			if (context->arguments) free(context->arguments);
			NCOT_DEBUG("ncot_context_free: 5 freeing context at 0x%x\n", context);
			free(context);
			*pcontext = NULL;
		} else
			NCOT_LOG_ERROR("Invalid context\n");
	} else
		NCOT_LOG_ERROR("Invalid argument (*context)\n");
}
#undef DEBUG
#define DEBUG 0

void
ncot_context_controlconnection_authenticate(struct ncot_context *context, struct ncot_connection *connection)
{
}

/* We need a way somehow to find out where a connection belongs to
 * when there is i/o action necessary. */
struct ncot_node
*ncot_context_get_node_by_connection(struct ncot_context *context, struct ncot_connection *connection)
{
	struct ncot_node *node;
	struct ncot_connection *nodeconnection;
	node = context->globalnodelist;
	while (node) {
		nodeconnection = node->connections;
		while (nodeconnection) {
			if (connection == nodeconnection)
				return node;
			nodeconnection = nodeconnection->next;
		}
		node = node->next;
	}
	/* Should return NULL at end of list when nothing is
	 * found. Should be covered by a test. */
	return node;
}

/* Enqueuing a connection into a context connections list means
 * enqueueing it, and remove it from all other lists where it makes no
 * sense. - We forget that. We only enqueue for now. */
void
ncot_context_enqueue_connection_connected(struct ncot_context *context, struct ncot_connection *connection)
{
	LL_APPEND(context->connections_connected, connection);
}

void
ncot_context_enqueue_connection_listen(struct ncot_context *context, struct ncot_connection *connection)
{
	LL_APPEND(context->connections_listen, connection);
}

void
ncot_context_enqueue_connection_closed(struct ncot_context *context, struct ncot_connection *connection)
{
	LL_APPEND(context->connections_closed, connection);
}

void
ncot_context_enqueue_connection_writing(struct ncot_context *context, struct ncot_connection *connection)
{
	/* We need to make sure our connection appears exactly one
	time in the writing list, reagardless of how often this
	function is called for that connection. There may be multiple
	calls because many packets can be queued in
	connection->packetlist */
	struct ncot_connection *writeconn;
	writeconn = context->connections_writing;
	while (writeconn) {
		if (connection == writeconn) return;
		writeconn = writeconn->next;
	}
	LL_APPEND(context->connections_writing, connection);
}
void
ncot_context_dequeue_connection_connected(struct ncot_context *context, struct ncot_connection *connection)
{
	LL_DELETE(context->connections_connected, connection);
}

void
ncot_context_dequeue_connection_listen(struct ncot_context *context, struct ncot_connection *connection)
{
	LL_DELETE(context->connections_listen, connection);
}

void
ncot_context_dequeue_connection_closed(struct ncot_context *context, struct ncot_connection *connection)
{
	LL_DELETE(context->connections_closed, connection);
}

void
ncot_context_dequeue_connection_writing(struct ncot_context *context, struct ncot_connection *connection)
{
	LL_DELETE(context->connections_writing, connection);
}
