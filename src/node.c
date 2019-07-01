#include <uuid.h>

#include "node.h"
#include "log.h"
#include "utlist.h"
#include "debug.h"

#ifdef DEBUG
#undef DEBUG
#endif
#define DEBUG 1
void
ncot_node_save(struct ncot_node *node, struct json_object *parent)
{
	int ret;
	char *string =  NULL;
	struct json_object *json;
	struct sockaddr_in *sockaddr;
	struct json_object *jsonobj;
	struct json_object *jsonarray;
	struct ncot_connection *connection;
	ret = uuid_export(node->uuid, UUID_FMT_STR, &string, NULL);
	if (ret != UUID_RC_OK) {
		NCOT_LOG_ERROR("ncot_node_save: unable to convert uuid, aborting save.\n");
		return;
	}
	node->json = json_object_new_string(string);
	json_object_object_add_ex(parent, "uuid", node->json, JSON_C_OBJECT_KEY_IS_CONSTANT);

	jsonarray = json_object_new_array();
	connection = node->connections;
	while (connection) {
		jsonobj = json_object_new_object();
		ncot_connection_save(connection, jsonobj);
		json_object_array_add(jsonarray, jsonobj);
		connection = connection->next;
		NCOT_LOG_VERBOSE("ncot_node_save: saved a connections\n");
	}
	json_object_object_add_ex(parent, "connections", jsonarray, JSON_C_OBJECT_KEY_IS_CONSTANT);
	NCOT_LOG_VERBOSE("ncot_node_save: node saved\n");
}

/* Load nodes from json object, concat as a list and return list
 * head. */
struct ncot_node*
ncot_nodes_new_from_json(struct json_object *jsonobj)
{
	struct ncot_node *node;
	struct ncot_node *nodelist = NULL;
	struct json_object *jsonnode;
	struct json_object *jsonvalue;
	const char *string;
	int ret;
	int numnodes;
	int i;
	numnodes = json_object_array_length(jsonobj);
	for (i=0; i<numnodes; i++) {
		jsonnode = json_object_array_get_idx(jsonobj, i);
		ret = json_object_object_get_ex(jsonnode, "uuid", &jsonvalue);
		if (! ret) {
			NCOT_LOG_WARNING("ncot_nodes_new_from_json: no field name \"uuid\" in json, skipping node\n");
			continue;
		}
		node = calloc(1, sizeof(struct ncot_node));
		if (!node) return node;
		uuid_create(&node->uuid);
		string = json_object_get_string(jsonvalue);
		ret = uuid_import(node->uuid, UUID_FMT_STR, string, strlen(string));
		if (ret != UUID_RC_OK) {
			NCOT_LOG_WARNING("ncot_nodes_new_from_json: error importing uuid from json, skipping node\n");
			ncot_node_free(&node);
			continue;
		}
		DL_APPEND(nodelist, node);
		node = NULL;
	}
	return nodelist;
}

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
		uuid_create(&node->uuid);
		uuid_make(node->uuid, UUID_MAKE_V1);
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
			if (node->uuid) uuid_destroy(node->uuid);
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

