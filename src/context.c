#define DEBUG 0

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <json-c/json.h>

#include "debug.h"
#include "error.h"
#include "context.h"
#include "utlist.h"
#include "node.h"
#include "identity.h"

struct ncot_context*
ncot_context_new()
{
	struct ncot_context *context;
	context = calloc(1, sizeof(struct ncot_context));
	return context;
}

int
ncot_context_parse_from_json(struct ncot_context *context) {
	struct json_object *jsonobj;
	const char *string;
	int ret;
	NCOT_ERROR_IF_NULL(context, "ncot_context_parse_from_json: invalid context argument");
	NCOT_ERROR_IF_NULL(context->json, "ncot_context_parse_from_json: invalid context->json argument");
	/* First read our context uuid */
	ret = json_object_object_get_ex(context->json, "uuid", &jsonobj);
	if (! ret) {
		NCOT_LOG_ERROR("ncot_context_parse_from_json: no field name \"uuid\" in json");
		return NCOT_ERROR;
	}
	uuid_create(&context->uuid);
	string = json_object_get_string(jsonobj);
	ret = uuid_import(context->uuid, UUID_FMT_STR, string, strlen(string));
	if (ret != UUID_RC_OK) {
		NCOT_LOG_ERROR("ncot_context_parse_from_json: error importing uuid from json");
		return NCOT_ERROR;
	}

	/* Next an identity object */
	ret = json_object_object_get_ex(context->json, "identity", &jsonobj);
	if (ret) {
		NCOT_DEBUG("ncot_context_parse_from_json: identity found\n");
		context->identity = ncot_identity_new_from_json(jsonobj);
	}

	/* Load nodes if any */
	ret = json_object_object_get_ex(context->json, "nodes", &jsonobj);
	if (ret) {
		NCOT_DEBUG("ncot_context_parse_from_json: nodes found\n");
		context->globalnodelist = ncot_nodes_new_from_json(jsonobj);
	}

	NCOT_LOG_VERBOSE("ncot_context_parse_from_json: Ok. uuid: %s\n", string);
	return NCOT_SUCCESS;
}

/*Basic initialization which is shared among the following two functions */
void
ncot_context_init_base(struct ncot_context *context)
{
	if (context) {
		context->globalnodelist = NULL;
		context->controlconnection = ncot_connection_new();
		ncot_connection_init(context->controlconnection, NCOT_CONN_CONTROL);
	} else {
		NCOT_LOG_WARNING("Invalid context passed to ncot_context_init_base\n");
	}
	NCOT_LOG_VERBOSE("context basic initialization\n");
}

/* This is called when there is no config file available. We need to
 * initialize as much as we can to have proper empty functionality */
void
ncot_context_init(struct ncot_context *context)
{
	if (context) {
		/*    context->config = ncot_config_new(); */
		ncot_context_init_base(context);
		uuid_create(&context->uuid);
		uuid_make(context->uuid, UUID_MAKE_V1);
		context->identity = ncot_identity_new();
		ncot_identity_init(context->identity);
	} else {
		NCOT_LOG_WARNING("Invalid context passed to ncot_context_init\n");
	}
}

/* This is called when a config file is available. Make initialization
 * depending on data found in config file */
#define NCOT_READ_BUFLEN 128
int
ncot_context_init_from_file(struct ncot_context *context, const char* filename)
{
	int fd;
	ssize_t r;
	char buf[NCOT_READ_BUFLEN];
	struct json_tokener *tokener;
	enum json_tokener_error jerr;
	ncot_context_init_base(context);
	fd = open(filename, O_RDONLY);
	if (fd <= 0) {
		NCOT_LOG_ERROR("ncot_context_init_from_file: Error opening config file %s\n", filename);
		return NCOT_ERROR;
	}
	tokener = json_tokener_new();
	if (!tokener) {
		NCOT_LOG_ERROR("ncot_context_init_from_file: Error allocating json tokener object");
		close(fd);
		return NCOT_ERROR;
	}
	do {
		r = read(fd, &buf, NCOT_READ_BUFLEN);
		context->json = json_tokener_parse_ex(tokener, buf, r);
	} while ((jerr = json_tokener_get_error(tokener)) == json_tokener_continue);
	close(fd);
	if (jerr != json_tokener_success) {
		NCOT_LOG_ERROR("ncot_context_init_from_file: json parse error: %s\n", json_tokener_error_desc(jerr));
		json_tokener_free(tokener);
		return NCOT_ERROR;
	}
 	json_tokener_free(tokener);
 	if (ncot_context_parse_from_json(context) != NCOT_SUCCESS) {
		NCOT_LOG_ERROR("ncot_context_init_from_file: Error parsing internal fields from json");
		return NCOT_ERROR;
	}
	NCOT_LOG_INFO("context loaded from file: %s.\n", filename);
	return NCOT_SUCCESS;
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

int
ncot_context_save_nodes(struct ncot_context *context, int fd)
{
}

#ifdef DEBUG
#undef DEBUG
#endif
#define DEBUG 1
int
ncot_context_save_state(struct ncot_context *context)
{
	int fd;
	int ret;
	struct json_object *jsonobj;
	struct json_object *jsonarray;
	char *uuidstring =  NULL;
	struct ncot_node *node;

	RETURN_ERROR_IF_NULL(context, "ncot_context_save_state: invalid context argument.");
	RETURN_ERROR_IF_NULL(context->arguments, "ncot_context_save_state: context argument not correctly initialized.");
	RETURN_ERROR_IF_NULL(context->arguments->config_file, "ncot_context_save_state: context argument not correctly initialized (arguments->config_file).");
	RETURN_ERROR_IF_NULL(context->identity, "ncot_context_save_state: context argument not correctly initialized (identity).");
	NCOT_LOG_VERBOSE("ncot_context_save_state: saving state to %s\n", context->arguments->config_file);
	fd = open(context->arguments->config_file, O_CREAT|O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (!fd > 0) {
		NCOT_LOG_ERROR("ncot_context_save_state: error opening config state file %s for saving\n", context->arguments->config_file);
		return NCOT_ERROR;
	}
	/* Let's start with an empty json root object */
	context->json = json_object_new_object();
	/* Store the contexts uuid */
	ret = uuid_export(context->uuid, UUID_FMT_STR, &uuidstring, NULL);
	if (ret != UUID_RC_OK) {
		NCOT_LOG_ERROR("ncot_context_save_state: unable to convert uuid of context.\n");
	}
	jsonobj = json_object_new_string(uuidstring);
	json_object_object_add_ex(context->json, "uuid", jsonobj, JSON_C_OBJECT_KEY_IS_CONSTANT);
	/* Store the identity object */
	jsonobj = json_object_new_object();
	json_object_object_add_ex(context->json, "identity", jsonobj, JSON_C_OBJECT_KEY_IS_CONSTANT);
	ncot_identity_save(context->identity, jsonobj);
	/* Store control connection */
	jsonobj = json_object_new_object();
	json_object_object_add_ex(context->json, "controlconnection", jsonobj, JSON_C_OBJECT_KEY_IS_CONSTANT);
	ncot_connection_save(context->controlconnection, jsonobj);

	/* Store our nodes */
	jsonarray = json_object_new_array();
	node = context->globalnodelist;
	while (node) {
		jsonobj = json_object_new_object();
		ncot_node_save(node, jsonobj);
		json_object_array_add(jsonarray, jsonobj);
		node = node->next;
		NCOT_LOG_VERBOSE("ncot_context_save_state: saved a node\n");
	};
	json_object_object_add_ex(context->json, "nodes", jsonarray, JSON_C_OBJECT_KEY_IS_CONSTANT);

	ret = json_object_to_fd(fd, context->json, JSON_C_TO_STRING_PRETTY);
	if (ret == -1) {
		NCOT_LOG_ERROR("ncot_context_save_state: error putting context->json: %s", json_util_get_last_err());
		return NCOT_ERROR;
	}
	NCOT_LOG_VERBOSE("ncot_context_save_state: saved to %s.\n", context->arguments->config_file);
	close(fd);
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
 			NCOT_DEBUG("ncot_context_free: 0 freeing context at 0x%x\n", context);
			ncot_context_save_state(context);
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
