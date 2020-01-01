#include <uuid.h>

#include "context.h"
#include "node.h"
#include "log.h"
#include "utlist.h"
#include "debug.h"
#include "error.h"
#include "db.h"
#include "ssh.h"

#ifdef DEBUG
#undef DEBUG
#endif
#define DEBUG 0

struct ncot_node*
ncot_node_new()
{
	struct ncot_node *node;
	node = calloc(1, sizeof(struct ncot_node));
	return node;
}

/* Load nodes from json object, concat as a list and return list
 * head. */
struct ncot_node*
ncot_nodes_new_from_json(struct ncot_context *context, struct json_object *jsonobj)
{
	struct ncot_node *node;
	struct ncot_node *nodelist = NULL;
	struct json_object *jsonnode;
	struct json_object *jsonvalue;
	struct json_object *jsonarray;
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
		if (!node->keyset) {
			node->keyset = ncot_ssh_keyset_new();
		}
		string = json_object_get_string(jsonvalue);
		ret = uuid_import(node->uuid, UUID_FMT_STR, string, strlen(string));
		if (ret != UUID_RC_OK) {
			NCOT_LOG_WARNING("ncot_nodes_new_from_json: error importing uuid from json, skipping node\n");
			ncot_node_free(&node);
			continue;
		}
		ret = json_object_object_get_ex(jsonnode, "connections", &jsonarray);
		if (ret) {
			NCOT_DEBUG("ncot_nodes_new_from_json: connections found\n");
			node->connections = ncot_connections_new_from_json(context, node, jsonarray);
		} else {
			NCOT_LOG_WARNING("ncot_nodes_new_from_json: no connection information found. Initialize with empty ones.\n");
			/* TODO: create proper empty connections for this node */
		}
		DL_APPEND(nodelist, node);
		node = NULL;
	}
	return nodelist;
}

/** A node may get passed with pre init fields here, so only fill in
 * the missing data */
void
ncot_node_init(struct ncot_context *context, struct ncot_node *node) {
	struct ncot_connection_list *connectionlist;
	int i;
	if (node) {
		if (!node->uuid) {
			uuid_create(&node->uuid);
			uuid_make(node->uuid, UUID_MAKE_V1);
			uuid_export(node->uuid, UUID_FMT_STR, &node->uuidstring, NULL);
		}
		if (!node->keyset) {
			node->keyset = ncot_ssh_keyset_new();
		}
		if (!node->connections) {
			/* Create some dangling connections */
			for (i=0; i<NCOT_NODE_CONNECTION_COUNT; i++) {
				connectionlist = ncot_connection_list_new();
				if (!connectionlist) {
					NCOT_LOG_WARNING("ncot_node_init: out of mem.\n");
					break;
				}
				connectionlist->connection = ncot_connection_new();
				if (!connectionlist->connection) {
					NCOT_LOG_WARNING("ncot_node_init: out of mem.\n");
					free(connectionlist);
					break;
				}
				ncot_connection_init(context, node, connectionlist->connection, NCOT_CONN_NODE);
				DL_APPEND(node->connections, connectionlist);
			}
		}
	} else {
		NCOT_LOG_WARNING("Invalid node passed to ncot_node_init\n");
	}
}

#ifdef DEBUG
#undef DEBUG
#endif
#define DEBUG 0
void
ncot_node_free(struct ncot_node **pnode) {
	struct ncot_node *node;
	struct ncot_connection_list *connectionlist;
	if (pnode) {
		node = *pnode;
		if (node) {
			if (node->uuid) uuid_destroy(node->uuid);
			if (node->uuidstring) free(node->uuidstring);
			connectionlist = node->connections;
			NCOT_DEBUG("ncot_node_free: before freeing connectionlist\n");
			while (connectionlist) {
				DL_DELETE(node->connections, connectionlist);
				ncot_connection_list_free(&connectionlist);
				connectionlist = node->connections;
			}
			NCOT_DEBUG("ncot_node_free: after freeing connectionlist\n");
			if (node->keyset) ncot_ssh_keyset_free(&node->keyset);
			free(node);
			*pnode = NULL;
		} else
			NCOT_LOG_ERROR("Invalid ncot_node\n");
	} else
		NCOT_LOG_ERROR("Invalid argument (*node)\n");
}

void
ncot_node_save(struct ncot_node *node, struct json_object *parent)
{
	int ret;
	char *string =  NULL;
	struct json_object *json;
	struct sockaddr_in *sockaddr;
	struct json_object *jsonobj;
	struct json_object *jsonarray;
	struct ncot_connection_list *connection;
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
		ncot_connection_save(connection->connection, jsonobj);
		json_object_array_add(jsonarray, jsonobj);
		connection = connection->next;
		NCOT_LOG_VERBOSE("ncot_node_save: saved a connections\n");
	}
	json_object_object_add_ex(parent, "connections", jsonarray, JSON_C_OBJECT_KEY_IS_CONSTANT);
	NCOT_LOG_VERBOSE("ncot_node_save: node saved\n");
}

void
ncot_node_authenticate_peer(struct ncot_node *node, struct ncot_connection *connection)
{
	/* We have the connection accepted and in the connected
	 * state. Lets authenticate the peer. */
	return;
}

int
ncot_node_is_connected(struct ncot_node *node)
{
	struct ncot_connection_list *connectionlist;
	int found = 0;
	RETURN_FAIL_IF_NULL(node, "ncot_node_is_connected: invalid node parameter\n");
	if (!node->connections) {
		NCOT_LOG_WARNING("ncot_node_is_connected: node without connections encountered\n");
		return NCOT_ERROR;
	}
	connectionlist = node->connections;
	while (connectionlist) {
		if (connectionlist->connection->status == NCOT_CONN_CONNECTED)
			found = 1;
		connectionlist = connectionlist->next;
	}
	return found;
}

struct ssh_key_struct*
ncot_node_get_private_key(struct ncot_node *node, enum ncot_ssh_keytype type, int autogenerate)
{
	struct ncot_ssh_keypair *keypair;
	int r;
	if (!node) return NULL;
	if (ncot_ssh_keyset_has_keytype(node->keyset, type)) {
		keypair = ncot_ssh_keyset_get_keypair(node->keyset, type);
		return keypair->key;
	} else {
		if (autogenerate) {
			r = ncot_ssh_keyset_generate_key(node->keyset, type);
			if (!r == NCOT_OK) {
				NCOT_LOG_ERROR("ncot_node_get_private_key: unable to autogenerate key of type %s.\n", ncot_ssh_keytype_to_char(type));
				return NULL;
			}
			keypair = ncot_ssh_keyset_get_keypair(node->keyset, type);
			return keypair->key;
		} else {
			NCOT_LOG_ERROR("ncot_node_get_private_key: no key of type %s available in keyset and autogenerate turned off.\n", ncot_ssh_keytype_to_char(type));
			return NULL;
		}
	}
}

struct ssh_key_struct*
ncot_node_get_public_key(struct ncot_node *node, enum ncot_ssh_keytype type)
{
	struct ncot_ssh_keypair *keypair;
	int r;
	if (!node) return NULL;
	if (!node->keyset) return NULL;
	if (ncot_ssh_keyset_has_keytype(node->keyset, type)) {
		keypair = ncot_ssh_keyset_get_keypair(node->keyset, type);
		return keypair->pkey;
	} else {
		NCOT_LOG_ERROR("ncot_node_get_public_key: no key of type %s available in keyset.\n", ncot_ssh_keytype_to_char(type));
		return NULL;
	}
}

/* Make existing keys of a node persistent. Different ways
 * implementable by ncot_db_* indirection functions */
int
ncot_node_persist_keys(struct ncot_context *context, struct ncot_node *node)
{
	return ncot_db_node_save_keys(context, node);
}

/* Load private key(s) */
int
ncot_node_load_key(struct ncot_context *context, struct ncot_node *node, int types)
{
	int failure = 0;

	if (!context || !node || !node->keyset) return NCOT_ERROR;
 	if (types & NCOT_SSH_KEYTYPE_RSA)
		if (ncot_db_node_load_key(context, node, NCOT_SSH_KEYTYPE_RSA) != NCOT_OK)
			failure = 1;
	if (types & NCOT_SSH_KEYTYPE_ECDSA_P256)
		if (ncot_db_node_load_key(context, node, NCOT_SSH_KEYTYPE_ECDSA_P256) != NCOT_OK)
			failure = 1;
	if (types & NCOT_SSH_KEYTYPE_ED25519)
		if (ncot_db_node_load_key(context, node, NCOT_SSH_KEYTYPE_ED25519) != NCOT_OK)
			failure = 1;
	return failure;
}

/* Load public key(s) */
int
ncot_node_load_pkey(struct ncot_context *context, struct ncot_node *node, int types)
{
	int failure = 0;

	if (!context || !node || !node->keyset) return NCOT_ERROR;
 	if (types & NCOT_SSH_KEYTYPE_RSA)
		if (ncot_db_node_load_pkey(context, node, NCOT_SSH_KEYTYPE_RSA) != NCOT_OK)
			failure = 1;
	if (types & NCOT_SSH_KEYTYPE_ECDSA_P256)
		if (ncot_db_node_load_pkey(context, node, NCOT_SSH_KEYTYPE_ECDSA_P256) != NCOT_OK)
			failure = 1;
	if (types & NCOT_SSH_KEYTYPE_ED25519)
		if (ncot_db_node_load_pkey(context, node, NCOT_SSH_KEYTYPE_ED25519) != NCOT_OK)
			failure = 1;
	return failure;
}

/* Load public and private key(s) */
int
ncot_node_load_keys(struct ncot_context *context, struct ncot_node *node, int types)
{
	int failure = 0;
	int r;
	/* return (ncot_node_load_key(context, node, types) &&
	 * ncot_node_load_pkey(context, node, types)); <- does not
	 * work as expected. Only the first function call gets
	 * executed at all.*/
	if (ncot_node_load_key(context, node, types) != NCOT_OK) failure = 1;
	if (ncot_node_load_pkey(context, node, types) != NCOT_OK) failure = 1;
	return failure;
}
