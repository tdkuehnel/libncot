#ifndef _NCOT_DB_H_
#define _NCOT_DB_H_

#include <libssh/libssh.h>

#include "node.h"
#include "context.h"

/** Provide an interface to use a real db backend when needed */

typedef int (*ncot_db_node_load_key_function)(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype type);
typedef int (*ncot_db_node_load_pkey_function)(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype type);
typedef int (*ncot_db_node_save_keys_function)(struct ncot_context *context, struct ncot_node *node);

extern ncot_db_node_load_key_function ncot_db_node_load_key_function_pointer;
extern ncot_db_node_load_pkey_function ncot_db_node_load_pkey_function_pointer;
extern ncot_db_node_save_keys_function ncot_db_node_save_keys_function_pointer;

/** General function calling interface */
void ncot_db_init();

int ncot_db_node_load_key(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype type);
int ncot_db_node_load_pkey(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype type);
int ncot_db_node_save_keys(struct ncot_context *context, struct ncot_node *node);

/** json like db function implementation */
int ncot_db_node_load_key_json(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype type);
int ncot_db_node_load_pkey_json(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype type);
int ncot_db_node_save_keys_json(struct ncot_context *context, struct ncot_node *node);

/** plain file function implementation with subdir per node*/
int ncot_db_node_load_key_file(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype type);
int ncot_db_node_load_pkey_file(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype type);
int ncot_db_node_save_keys_file(struct ncot_context *context, struct ncot_node *node);

#endif /* _NCOT_DB_H_ */
