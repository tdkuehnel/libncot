#define DEBUG 0

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "debug.h"
#include "error.h"
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

int
ncot_context_parse_from_json(struct ncot_context *context) {
	struct json_object *jsonuuid;
	const char *string;
	int ret;
	NCOT_ERROR_IF_NULL(context, "ncot_context_parse_from_json: invalid context argument");
	NCOT_ERROR_IF_NULL(context->json, "ncot_context_parse_from_json: invalid context->json argument");
	ret = json_object_object_get_ex(context->json, "uuid", &jsonuuid);
	if (! ret) {
		NCOT_LOG_ERROR("ncot_context_parse_from_json: no field name \"uuid\" in json");
		return NCOT_ERROR;
	}
	uuid_create(&context->uuid);
	string = json_object_get_string(jsonuuid);
	ret = uuid_import(context->uuid, UUID_FMT_STR, string, strlen(string));
	if (ret != UUID_RC_OK) {
		NCOT_LOG_ERROR("ncot_context_parse_from_json: error importing uuid from json");
		return NCOT_ERROR;
	}

	NCOT_LOG_INFO("ncot_context_parse_from_json: Ok. uuid: %s\n", string);
	return NCOT_SUCCESS;
}

#define NCOT_READ_BUFLEN 128

struct ncot_context*
ncot_context_new_from_file(const char* filename)
{
	int fd;
	ssize_t r;
	char buf[NCOT_READ_BUFLEN];
	struct ncot_context *context;
	struct json_tokener *tokener;
	enum json_tokener_error jerr;
	fd = open(filename, O_RDONLY);
	FD_ERROR(fd, "ncot_context_new_from_file: Error opening file");
	context = ncot_context_new();
	if (!context) {
		NCOT_LOG_ERROR("ncot_context_new_from_file: Error allocating context object");
		close(fd);
		return NULL;
	}
	tokener = json_tokener_new();
	if (!tokener) {
		NCOT_LOG_ERROR("ncot_context_new_from_file: Error allocating json tokener object");
		ncot_context_free(&context);
		close(fd);
	}
	do {
		r = read(fd, &buf, NCOT_READ_BUFLEN);
		context->json = json_tokener_parse_ex(tokener, buf, r);
	} while ((jerr = json_tokener_get_error(tokener)) == json_tokener_continue);
	close(fd);
	if (jerr != json_tokener_success) {
		NCOT_LOG_ERROR("ncot_context_new_from_file: json parse error: %s\n", json_tokener_error_desc(jerr));
		json_tokener_free(tokener);
		ncot_context_free(&context);
		return NULL;
	}
 	json_tokener_free(tokener);
 	if (ncot_context_parse_from_json(context) != NCOT_SUCCESS) {
		NCOT_LOG_ERROR("ncot_context_new_from_file: Error parsing internal fields from json");
		ncot_context_free(&context);
		return NULL;
	}
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
			if (context->shell) ncot_shell_free(&context->shell);
			if (context->uuid) uuid_destroy(context->uuid);
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
