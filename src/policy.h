#ifndef _NCOT_POLICY_
#define _NCOT_POLICY_

#include <json-c/json.h>
#include "uthash.h"

/** Policies.
 *
 * Every ring has its own set of policies where the nodes have a
 * consensus about of what is necessary. For example, for new unknown,
 * untrusted nodes to get into the ring there could be a policy of
 * "Every other node has to vote yes for the new participant to join",
 * or "only two neighbour nodes need to trust the new one" and so
 * forth.  Another part of the policy spectrum could be "Every node
 * passing SPAM into this ring gets excluded". Or "No anonymous nodes
 * allowed". */

/** Reputation
 *
 * Policies are related to reputation. For the reputation model to
 * work we need signed trusted reputation tokens, or marks. When a new
 * node anounces its repuation during a connect request, the ring node
 * should be able to contact the issuer of the reputation tokens and
 * verify the integrity of the announced token.  But this is at first
 * hand only one possible action.  We can send out into the whole
 * network of trust a repuation request with the identity
 * involved. When there comes nothing in response, it is a vanilla new
 * identity where everbody of us starts with, with its intial basic
 * level of trust every new user gains. On the other end, the amount
 * of responses alone could reveal a lot of the identity
 * involved. When someone says: "I have a good record of this identity
 * from years ago" could mean much. Lets take the worst case scenario:
 * Someone tries to max out the possibilities with fake (bot)
 * identities. He can generate a whole network of trust of his
 * bots. We need to give the honest people the tools at hand to decide
 * on their own whom to trust and whom not. Its the identity with its
 * records saved all over the nodes he had contact with (and gained,
 * lost reputation) whats makes up the identity. Where is the fake bot
 * net on stackoverflow which gives fake good reputations ? This
 * should work in a distributed network of losely connected nodes,
 * too.
 */

#define NCOT_POLICY_BRIEF_LENGTH 256
#define NCOT_POLICY_CATEGORY_LENGTH 64
#define NCOT_POLICY_MAX_TEXT_LEN 2048

struct ncot_policy;
/** Policy A policy is to passed around in connection requests and
 * such. A policy needs to be representable to a user so that he or
 * she can read, understand and decline or accept it. Its so simple.
 *
 * Everyone can create its own policy, but existent policies can be
 * reused so there is no really need to inevnt the wheel over and over
 * again. So in the long run we need some kind of network wide policy
 * search facility, and should be able to distinguish two policies
 * from each other. We may group policies into groups (all
 * authenticity policies in one group, define your own group.).
 *
 * With a search request for existing policies into the network we can
 * present the user in question a list of preexistend policies to
 * choose from, grouped by category. */
struct ncot_policy {
	char brief[NCOT_POLICY_BRIEF_LENGTH]; /* Brief description of the policy */
	char category[NCOT_POLICY_CATEGORY_LENGTH]; /*Category a policy belongs to */
	char *text; /* Long description */
	UT_hash_handle hh; /* uthash required */
	struct json_object *json;
};

struct ncot_policy* ncot_policy_new();
void ncot_policy_init(struct ncot_policy *policy);
void ncot_policy_free(struct ncot_policy **ppolicy);
void ncot_policy_set_brief(struct ncot_policy *policy, char *brief);
void ncot_policy_set_category(struct ncot_policy *policy, char *category);
void ncot_policy_set_text(struct ncot_policy *policy, char *text);
void ncot_policy_save_to_json(struct ncot_policy *policy, struct json_object *parent);
struct ncot_policy* ncot_policies_new_from_json(struct json_object *jsonobj);

#endif
