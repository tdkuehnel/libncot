#ifndef _NCOT_POLICY_
#define _NCOT_POLICY_

/* Policies.
 *
 * Every ring has its own set of policies where the nodes have a
 * consensus about of what is necessary. For example, for new unknown,
 * untrusted nodes to get into the ring there could be a policy of
 * "Every other node has to vote yes for the new participant to join",
 * or "only two neighbour nodes need to trust the new one" and so
 * forth.  Another part of the policy spectrum could be "Every node
 * passing SPAM into this ring gets excluded". Or "No anonymous nodes
 * allowed". */

/* Policies are related to reputation. For the reputation model to
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

#endif
