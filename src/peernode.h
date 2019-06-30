#ifndef _NCOT_PEER_NODE_H_
#define _NCOT_PEER_NODE_H_

/* A peer node structure stores information about the other peers in a
 * ring. When as a node we are loosing the connection to our ring by
 * whatever reason, we want to be able to reconnect again, even when
 * our own or the ipaddresses of our direct neighbours change. So we
 * keep a copy of the addresses of every node of the whole ring.*/

struct ncot_peer_node;
struct ncot_peer_node {
	struct ncot_peer_node *prev;
	struct ncot_peer_node *next;
}

#endif


