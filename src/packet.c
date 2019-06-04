#include <arpa/inet.h>

#define DEBUG 0
#include "debug.h"
#include "packet.h"
#include "error.h"

int
ncot_packet_print(struct ncot_packet *packet)
{
	char string[128];
	uint16_t length;
	RETURN_FAIL_IF_NULL(packet, "ncot_packet_print: invalid packet argument.");
	RETURN_FAIL_IF_NULL(packet->data, "ncot_packet_print: invalid packet->data argument.");
	strncpy(string, packet->data->magic, 4);
	string[4] = 0;
	NCOT_LOG_INFO("packet at 0x%x: %s\n", packet, string);
	strncpy(string, packet->data->version, 8);
	string[8] = 0;
	NCOT_LOG_INFO("packet at 0x%x: %s\n", packet, string);
	strncpy(string, packet->data->subtype, 4);
	string[4] = 0;
	NCOT_LOG_INFO("packet at 0x%x: %s\n", packet, string);
	length = ntohs(packet->data->length);
	NCOT_LOG_INFO("packet at 0x%x: %i bytes\n", packet, length);
	return 0;
}

int
ncot_packet_is_subtype(struct ncot_packet *packet, const char subtype[4])
{
	struct ncot_packet_data *packetdata;
	RETURN_FAIL_IF_NULL(packet, "ncot_packet_is_subtype: invalid packet argument.");
	packetdata = packet->data;
	return strncmp(subtype, packetdata->subtype, 4);
}

void
ncot_packet_set_subtype(struct ncot_packet *packet, const char subtype[4])
{
	struct ncot_packet_data *packetdata;
	RETURN_IF_NULL(packet, "ncot_packet_set_subtype: invalid packet argument.");
	packetdata = packet->data;
	memcpy(packetdata->subtype, subtype, 4);
}

struct ncot_packet*
ncot_packet_new()
{
	struct ncot_packet *packet;
	packet = calloc(1, sizeof(struct ncot_packet));
	return packet;
}

struct ncot_packet*
ncot_packet_new_with_data(const char *data, int length)
{
	struct ncot_packet *packet;
	packet = ncot_packet_new();
	RETURN_NULL_IF_NULL(packet, "ncot_packet_new_with_data: out of memory");
	packet->data = malloc(length);
	RETURN_NULL_IF_NULL(packet->data, "ncot_packet_new_with_data: out of memory");
	memcpy(packet->data, data, length);
	packet->length = length;
	return packet;
}

struct ncot_packet*
ncot_packet_new_with_message(const char *message, int length, enum ncot_packet_type type)
{
	struct ncot_packet *packet;
	char *pointer;
	packet = ncot_packet_new();
	RETURN_NULL_IF_NULL(packet, "ncot_packet_new_with_message: out of memory");
	packet->data = calloc(1, length + NCOT_PACKET_DATA_HEADER_LENGTH);
	RETURN_NULL_IF_NULL(packet->data, "ncot_packet_new_with_message: out of memory");
	NCOT_DEBUG("ncot_packet_new_with_message: %s, %i\n", message, length);
	pointer = (char*)packet->data;
	pointer += NCOT_PACKET_DATA_HEADER_LENGTH;
	NCOT_DEBUG("ncot_packet_new_with_message: pointer     : 0x%x\n", pointer);
	NCOT_DEBUG("ncot_packet_new_with_message: packet->data: 0x%x\n", packet->data);
	memcpy(pointer, message, length);
	packet->data->length = htons(length);
	switch (type) {
	case NCOT_PACKET_COMMAND:
		memcpy(packet->data->subtype, NCOT_PACKET_IDENTIFIER_COMMAND, 4);
	case NCOT_PACKET_RING_INTEGRITY:
		memcpy(packet->data->subtype, NCOT_PACKET_IDENTIFIER_RINGINTEGRITY, 4);
	case NCOT_PACKET_QUIT:
		memcpy(packet->data->subtype, NCOT_PACKET_IDENTIFIER_QUIT, 4);
	}
	memcpy(packet->data->magic, NCOT_MAGIC, 4);
	memcpy(packet->data->version, NCOT_VERSION, 8);
	packet->length = length + NCOT_PACKET_DATA_HEADER_LENGTH;
	NCOT_DEBUG_HEX("packetdata before send", packet->data, NCOT_PACKET_DATA_HEADER_LENGTH + length);
	return packet;
}

int
ncot_packet_set_data(struct ncot_packet *packet, const char *message, int length)
{
	RETURN_FAIL_IF_NULL(packet, "ncot_packet_set_data: invalid packet argument.");
	if (!packet->data) {
		packet->data = malloc(length);
	} else {
		if (packet->length != length) {
			free(packet->data);
			packet->data = malloc(length);
		}
	}
	RETURN_FAIL_IF_NULL(packet->data, "ncot_packet_set_data: out of memory.");
	packet->length = length;
	memcpy(packet->data, message, length);
	return packet->length;
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

