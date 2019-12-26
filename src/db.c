#include "error.h"
#include "db.h"

ncot_db_node_get_pkey_function ncot_db_node_get_pkey_function_pointer = NULL;
ncot_db_node_save_pkeys_function ncot_db_node_save_pkeys_function_pointer = NULL;

void
ncot_db_init()
{
	ncot_db_node_get_pkey_function_pointer = &ncot_db_node_get_pkey_file;
	ncot_db_node_save_pkeys_function_pointer = &ncot_db_node_save_pkeys_file;
}

/** general calling function interface */
struct ssh_key_struct*
ncot_db_node_get_pkey(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype keytype)
{
	return (*ncot_db_node_get_pkey_function_pointer)(context, node, keytype);
}

int
ncot_db_node_save_pkeys(struct ncot_context *context, struct ncot_node *node)
{
	return (*ncot_db_node_save_pkeys_function_pointer)(context, node);
}


/** json implementation */
struct ssh_key_struct*
ncot_db_node_get_pkey_json(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype keytype)
{
}

int
ncot_db_node_save_pkeys_json(struct ncot_context *context, struct ncot_node *node)
{
}

/** plain file implementation with subdir per node */
struct ssh_key_struct*
ncot_db_node_get_pkey_file(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype keytype)
{
}

int
ncot_db_node_save_pkeys_file(struct ncot_context *context, struct ncot_node *node)
{
	if (!context || !node) {
		NCOT_LOG_ERROR("ncot_db_node_save_pkeys_file: invalid parameters\n");
		return NCOT_ERROR;
	}
	if (!node->keyset) {
		NCOT_LOG_ERROR("ncot_db_node_save_pkeys_file: node without keyset\n");
		return NCOT_ERROR;
	}
}

