#include "ring.h"
#include "error.h"
#include "utlist.h"

struct ncot_ring_context*
ncot_ring_context_new()
{
	struct ncot_ring_context *ringcontext;
	ringcontext = calloc(1, sizeof(struct ncot_ring_context));
	return ringcontext;
}

void
ncot_ring_context_init(struct ncot_ring_context *ringcontext)
{
	ringcontext->encryption = NCOT_ENCRYPTION_BASIC;
}

void
ncot_ring_context_free(struct ncot_ring_context **pringcontext)
{
	struct ncot_ring_context *ringcontext;
	struct ncot_policy *policy;
	struct ncot_policy *poltmp;
	if (pringcontext) {
		ringcontext = *pringcontext;
		if (ringcontext) {
			DL_FOREACH_SAFE(ringcontext->policies, policy, poltmp) {
				DL_DELETE(ringcontext->policies, policy);
				ncot_policy_free(&policy);
			}
			free(ringcontext);
			*pringcontext = NULL;
		} else
			NCOT_LOG_ERROR("ncot_ring_context_free: Invalid ncot_ring_context\n");
	} else
		NCOT_LOG_ERROR("ncot_ring_context_free: Invalid argument (*ringcontext)\n");
}

/** Deep copy and append a policy to the ring context. */
void
ncot_ring_context_add_policy(struct ncot_ring_context *ring, struct ncot_policy *policy)
{
	struct ncot_policy *newpolicy;
	if (!ring) {
		NCOT_LOG_ERROR("ncot_ring_context_add_policy: Invalid argument ring\n");
		return;
	}
	if (!policy) {
		NCOT_LOG_ERROR("ncot_ring_context_add_policy: Invalid argument policy\n");
		return;
	}
	newpolicy = ncot_policy_copy_deep(policy);
	DL_APPEND(ring->policies, newpolicy);
}
