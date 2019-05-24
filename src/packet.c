#include "packet.h"
#include "error.h"

struct ncot_packet*
ncot_packet_new()
{
	struct ncot_packet *packet;
	packet = calloc(1, sizeof(struct ncot_packet));
	return packet;
}

struct ncot_packet*
ncot_packet_new_with_data(const char *message, int length)
{
	struct ncot_packet *packet;
	packet = ncot_packet_new();
	RETURN_NULL_IF_NULL(packet, "ncot_packet_new_with_data: out of mem");
	packet->data = malloc(length);
	RETURN_NULL_IF_NULL(packet->data, "ncot_packet_new_with_data: out of mem");
	memcpy(packet->data, message, length);
	packet->length = length;
}

void
ncot_packet_free(struct ncot_packet **ppacket)
{
	struct ncot_packet *packet;
	if (ppacket) {
		packet = *ppacket;
		if (packet) {
			if (packet->data) free(packet->data);
			free(packet);
			*ppacket = NULL;
		} else
			NCOT_LOG_ERROR("Invalid ncot_packet\n");
	} else
		NCOT_LOG_ERROR("Invalid argument (*packet)\n");
}

