#ifndef _NCOT_SSH_H_
#define _NCOT_SSH_H_

#include <libssh/libssh.h>

/** We go the way to separate the crypto layer from the nodes
 * layer. This is more work, but we want to USE established well known
 * crypto patterns and software, not unnecessarily extend it.
 *
 * So when a new connection request comes in to a listening connection
 * of a node, we look up the offered public key if it is known to the
 * current node context, and expected in the case of a dropped
 * connection. When a well known public key is offered, we can assume
 * we have the same node on the other side as before the connection
 * dropped.
 *
 * When the public key is unknown, and we have an intact ring on the
 * other side, we can assure that the requesting node is the one it
 * pretends by sending a packet around in the other direction and wait
 * for the answer. 
*/

/* our supported libssh keytypes usable as a bitfield */

enum ncot_ssh_keytype {
	NCOT_SSH_KEYTYPE_RSA = 1,
	NCOT_SSH_KEYTYPE_ECDSA_P256 = 2,
	NCOT_SSH_KEYTYPE_ECDSA_P384 = 4,
	NCOT_SSH_KEYTYPE_ECDSA_P512 = 8,
	NCOT_SSH_KEYTYPE_ED25519 = 16
};

struct ncot_ssh_keypair {
	/* public key */
	struct ssh_key_struct *pkey;
	/* private key */
	struct ssh_key_struct *key;
	enum ncot_ssh_keytype type;
};

/* rsa, ECDSA, ED25519 */
#define NCOT_SSH_KEYSET_NUMS 5

struct ncot_ssh_keyset {
	struct ncot_ssh_keypair *keypairs[NCOT_SSH_KEYSET_NUMS];
};

/* general calling interface */

struct ncot_ssh_keypair* ncot_ssh_keypair_new();
int ncot_ssh_keypair_init(struct ncot_ssh_keypair *keypair, enum ncot_ssh_keytype type);
void ncot_ssh_keypair_free(struct ncot_ssh_keypair **pkeypair);

struct ncot_ssh_keyset* ncot_ssh_keyset_new();
int ncot_ssh_keyset_init(struct ncot_ssh_keyset *keyset, int types);
int ncot_ssh_keyset_has_keytype(struct ncot_ssh_keyset *keyset, enum ncot_ssh_keytype type);
void ncot_ssh_keyset_free(struct ncot_ssh_keyset **pkeyset);

#endif /* _NCOT_SSH_H_ */
