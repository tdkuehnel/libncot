#ifndef _NCOT_PACKET_H_
#define _NCOT_PACKET_H_

/* We need a packet to send around. */

struct ncot_packet;
struct ncot_packet {
	char *data;
	int length;
	ncot_packet *next;
}

#endif
