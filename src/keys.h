#ifndef _NCOT_KEYS_H_
#define _NCOT_KEYS_H_

/** We need a way to store and retrieve ssh2 authorized and ssh2 known
 * hosts public keys (which are in our use case used
 * interchangeably). In effect we make no distinction in which of the
 * both files a public key lives as the whole client-server thing is
 * abstracted up one level and gone ...
 *
 * As we need to associate ssh2 public keys with nodes (for the
 * technical lower level) and identities (higher level), a relational
 * data base approach to store and retrieve the keys looks reasonable
 * for the mid- to long way approach. (sqlite?) postgres ! :)
 *
 * For the proof of concept we go with a json file per identity.
 */

#include "context.h"
#include "node.h"

#include <libssh/libssh.h>

#define NCOT_PUBLIC_KEYS_FILE "public_keys.json"
#define NCOT_PRIVATE_KEYS_FILE "private_keys.json"

int ncot_key_is_known(struct ncot_context *context, struct ssh_key_struct *key);
struct ssh_key_struct *ncot_node_get_public_key(struct ncot_context *context, struct ncot_node *node);
struct ssh_key_struct *ncot_node_get_private_key(struct ncot_context *context, struct ncot_node *node);
int ncot_node_save_public_key(struct ncot_context *context, struct ncot_node *node, struct ssh_key_struct *key);
int ncot_node_save_private_key(struct ncot_context *context, struct ncot_node *node, struct ssh_key_struct *key);

#endif /* _NCOT_KEYS_H_ */
