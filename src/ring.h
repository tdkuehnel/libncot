#ifndef _NCOT_RING_H_
#define _NCOT_RING_H_

#include "policy.h"

/** A ring consists of the circular connected nodes. Node members
 * share the common policies of the ring. A set of basic policy
 * settings, like minimal or allowed encryption shemes and strength,
 * are set during first creation of the ring. Those settings can be
 * adapted during a rings life cycle if the participating nodes choose
 * to do so in a trusted sense. That means, every node not fully
 * complying with the new rings policy settings can choose to leave
 * the ring or form another ring with all the other nodes not
 * complying. In the end, every ring of trust represents not only
 * trusted relationships, but also common sense in ring policy
 * settings.
 *
 * For now only required enryption settings come to mind.
 */

enum ncot_encryption_setting {

	/* This represents the TLS encryption settings needed to
	 * establish an untrusted connection when a node wants to join
	 * a ring. The authenticity has to be ensured out of
	 * band. Some unique security token may be generated and
	 * presented to the user through the UI to have it availbale
	 * for our of band transmission. */
	NCOT_ENCRYPTION_TOFU,

	/* These are encryption settings used for node to node
	 * communication inside a trusted ring structure. The
	 * authenticity of the neighbour node can be assured through
	 * the 2 way property of the connection paths the other way
	 * around trough the intact ring. */
	NCOT_ENCRYPTION_BASIC

};

struct ncot_ring_context;

struct ncot_ring_context {
	/* This may be entirely replaced by a policy in the future */
	enum ncot_encryption_setting encryption;

	/* Deep copies of policies for this ring */
	struct ncot_policy *policies;
};

struct ncot_ring_context* ncot_ring_context_new();
void ncot_ring_context_init(struct ncot_ring_context *ringcontext);
void ncot_ring_context_free(struct ncot_ring_context **pringcontext);
void ncot_ring_context_add_policy(struct ncot_ring_context *ring, struct ncot_policy *policy);

#endif
