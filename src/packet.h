#ifndef _NCOT_PACKET_H_
#define _NCOT_PACKET_H_

/* We need a packet to send around. */

struct ncot_packet;
struct ncot_packet {
	char *data;
	int length;
	int index;
	struct ncot_packet *next;
};

struct ncot_packet *ncot_packet_new();
struct ncot_packet *ncot_packet_new_with_data(const char *message, int length);
void ncot_packet_free(struct ncot_packet **ppacket);

#endif
