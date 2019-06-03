#ifndef _NCOT_PACKET_H_
#define _NCOT_PACKET_H_

#include <stdint.h>

/* We need a packet to send around. */

struct ncot_packet;
struct ncot_packet_data;

struct ncot_packet {
	struct ncot_packet_data *data;
	int length;
	int index;
	struct ncot_packet *next;
};

#define NCOT_PACKET_IDENTIFIER_COMMAND "CMND"
#define NCOT_PACKET_IDENTIFIER_RESPONSE "RSPN"
#define NCOT_PACKET_IDENTIFIER_QUIT "QUIT"

struct ncot_packet_data {
	char magic[4];
	char version[8];
	char subtype[4];
	uint16_t length; /* This is the length of the following data
			  * only */
	char data[];
};

#define NCOT_PACKET_VALID_MIN_LENGTH 18
#define NCOT_PACKET_DATA_HEADER_LENGTH NCOT_PACKET_VALID_MIN_LENGTH

struct ncot_packet *ncot_packet_new();
struct ncot_packet *ncot_packet_new_with_data(const char *message, int length);
int ncot_packet_print(struct ncot_packet *packet);
int ncot_packet_set_data(struct ncot_packet *packet, const char *message, int length);
void ncot_packet_set_subtype(struct ncot_packet *packet, const char subtype[4]);
int ncot_packet_is_subtype(struct ncot_packet *packet, const char subtype[4]);
void ncot_packet_free(struct ncot_packet **ppacket);

#endif
