#ifndef _NCOT_DB_H_
#define _NCOT_DB_H_

#include <libssh/libssh.h>

#include "node.h"
#include "context.h"

/** Provide an interface to use a real db backend when needed */


typedef struct ssh_key_struct* (*ncot_db_node_get_pkey_function)(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype keytype);
typedef  int (*ncot_db_node_save_pkeys_function)(struct ncot_context *context, struct ncot_node *node);

extern ncot_db_node_get_pkey_function ncot_db_node_get_pkey_function_pointer;
extern ncot_db_node_save_pkeys_function ncot_db_node_save_pkeys_function_pointer;

/** General function calling interface */
void ncot_db_init();
struct ssh_key_struct*
ncot_db_node_get_pkey(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype keytype);
int
ncot_db_node_save_pkeys(struct ncot_context *context, struct ncot_node *node);


/** json like db function implementation */
struct ssh_key_struct*
ncot_db_node_get_pkey_json(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype keytype);
int
ncot_db_node_save_pkeys_json(struct ncot_context *context, struct ncot_node *node);

/** plain file function implementation with subdir per node*/
struct ssh_key_struct*
ncot_db_node_get_pkey_file(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype keytype);
int
ncot_db_node_save_pkeys_file(struct ncot_context *context, struct ncot_node *node);

#endif /* _NCOT_DB_H_ */
