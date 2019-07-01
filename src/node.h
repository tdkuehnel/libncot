#ifndef NCOT_NODE
#define NCOT_NODE

#include <uuid.h>
#include <json-c/json.h>

#include "connection.h"

struct ncot_node;
/*!A node is a possible participant in a circle of other nodes. Every
   node has three possible encrypted connections, two connections for
   each direction of the ring it possibly participates in, and one for
   incoming participating requests from other, untrusted nodes. A node
   can have none, one or two connections permanently connected, while
   the third connection is only used during a connection request.

   Before there is any ring of trusted connections, there are at least
   two nodes. In the beginning, those nodes are unconnected, but they
   are maintained by its daemons running on any host connected to the
   Internet. All three connection ports of both nodes are open and
   waiting for connection requests from other nodes from any where on
   the Internet. So somehow one of the node connects with one of its
   open port to one of the other nodes open port. The process in
   finding the other node on the Internet involves some kind of
   communication beforehand. During this communication, a secret token
   MUST be exchanged to make it possible to establish a secure
   connection over those involved two connection request ports. The
   use of CA signed certificate based protocols and mechanism may
   provide such secure data channels to exchange a pre shared secret.

   So in the beginning, with only two nodes, we have no
   ring and so can not benefit from its inherent advantage, the two
   way communication path.

   Once those two nodes have established their secured, single
   connection, there are two more secure connections possible, as
   there are two more secure ports available per node. The quality of
   the secret exchange process involved when two nodes prepare for a
   new ring of trust is vital - should it fail, the whole ring may be
   compromised in the future and thus the nodes failing in beeing
   trustworthy may get excluded when all the remaining nodes decide to
   form a new ring, this time with trusted, secured connections.

   So for now we have two nodes, lets say they have managed it to
   establish a secure connection by sharing their secret in a
   apropriate manner. Now comes the third node, requesting a
   connection at one of the open ports of the two nodes which are
   already secure connected. As we still have no second data channel
   available to validate our diffie hellman generated key pairs, the
   process is the same as with the two beginning nodes. A secret has
   to be pre shared to establish this second two point secure
   connection.

   Now comes the magic. We have one node with two secure connections
   in the middle, and on each end a node with only one secure
   connection, which is each to the node in the middle. Imagine the
   shape of the letter V. Both nodes at the end, those two with only
   one connection to the node in the middle have a secure data path to
   the other node at the other end of the V already established, just
   over the third node in the middle. Thus both end nodes can use
   a simple diffie hellman key exchange mechanism to establish a secure
   connection to each others port, by verfiying the key integrity over
   the already established secure connection path over the trusted middle
   man. A trusted man in the middle counter attack so to say.

   The shape of the connection pattern has changed to that of a
   triangle.

   Enlargen the ring is easy, a new node requests participation by
   contacting one of the nodes of the ring on its free connection
   port. The process involved is the same as with two nodes only, both
   nodes need to exchange their secret somehow in a secure way, to
   make it sure they establish a secure connection between each
   other. Then, the node already participating in the ring requests
   one of its direct neighbour nodes to establish a secure connection
   to the new node. A simple diffie hellmann key exchange does the
   trick here, as the integrity of the keys can be established over
   the two nodes already participating in the ring. The both formerly
   directly secure connected neighbours open up their connection to
   each other to get their open free ports back, the ring has grown by
   one node and form the shape of a square.

   The integrity of a ring of nodes can be assured in that it is
   possible to send an integrity token in one direction over the
   ring. When it arrives on the other permanetly connected connection,
   the ring integrity is intact. It is possible for every node to send
   alive tokens around to inform the other nodes it is still
   participating.

   When a connection to a neighbour drops, this can have several
   reasons. A neighbour goes offline the Internet or shuts
   its daemon or crashes or decides to leave the ring. A node should
   check immediately in the other direction where the end of the ring
   is and connect to that open end - a simple diffie hellman key
   exchange does the trick as a secure data path is still available.
   When the other connection is down, too, our node may be excluded
   from the ring, our network connection is down or our other
   neighbour has gone offline, crashed or shutdown at the same time.

   Redundancy of shared secrets in rings of trust. Once we
   participated in an established secured ring of trust, we can share
   secrets with every other participating node. Those secrets can be
   used to reestablish secure connections and form rings instantly after
   power failure or data transmission failure of any kind.

   Excluding a node which can no longer be trusted is as simple as
   revoking trust in the secrets shared with such a node - a node can
   not force a connection, a connection is based on trust.

   Every user, or daemon instance as for now only one user per daemon
   is allowed, can have multiple nodes running, and so can be
   connected to multiple rings of nodes. Actually the daemon is the
   place where any interconnection communication between rings
   occurs.
*/
struct ncot_node {
	struct ncot_connection *connections;
	struct uuid_st *uuid;
	struct ncot_node *next;
	struct ncot_node *prev;
	struct json_object *json;
};

/**Serialize a node into a json representation.*/
void ncot_node_save(struct ncot_node *node, struct json_object *parent);
/** Create a new, empty node*/
struct ncot_node *ncot_node_new();
/** Free the node pointed to by pnode, and set its pointer to
 * NULL. Note the extra indirection. */
void ncot_node_free(struct ncot_node **pnode);
/** This is still unused at the moment. */
void ncot_node_authenticate_peer(struct ncot_node *node, struct ncot_connection *connection);
/** Init the provided node structure. At the moment only generates a
 * new uuid. */
void ncot_node_init(struct ncot_node *node);
/** Create a new node and read some node data and connection
 * information from the provided json object */
struct ncot_node* ncot_nodes_new_from_json(struct json_object *jsonobj);

#endif

