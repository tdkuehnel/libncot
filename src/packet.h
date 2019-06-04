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

#define NCOT_MAGIC "NCOT"
#define NCOT_VERSION "00.00.01"
#define NCOT_PACKET_IDENTIFIER_COMMAND "CMND"
#define NCOT_PACKET_IDENTIFIER_RESPONSE "RSPN"
#define NCOT_PACKET_IDENTIFIER_RINGINTEGRITY "RITG"
#define NCOT_PACKET_IDENTIFIER_QUIT "QUIT"

enum ncot_packet_type {
	NCOT_PACKET_COMMAND,
	NCOT_PACKET_RING_INTEGRITY,
	NCOT_PACKET_QUIT
};

struct ncot_packet_data {
	char magic[4];
	char version[8];
	char subtype[4];
	uint16_t length; /* This is the length of the following data
			  * only */
	char data[];
};

#define NCOT_PACKET_VALID_MIN_LENGTH 18
#define NCOT_PACKET_DATA_HEADER_LENGTH 18

struct ncot_packet *ncot_packet_new();
struct ncot_packet *ncot_packet_new_with_data(const char *data, int length);
struct ncot_packet *ncot_packet_new_with_message(const char *message, int length, enum ncot_packet_type type);
int ncot_packet_print(struct ncot_packet *packet);
int ncot_packet_set_data(struct ncot_packet *packet, const char *message, int length);
void ncot_packet_set_subtype(struct ncot_packet *packet, const char subtype[4]);
int ncot_packet_is_subtype(struct ncot_packet *packet, const char subtype[4]);
void ncot_packet_free(struct ncot_packet **ppacket);

#endif
