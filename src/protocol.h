#ifndef _NCOT_PROTOCOL_
#define _NCOT_PROTOCOL_

/* libncot daemons use a simple fixed packet sized communication
   protocol over the dedicated, encrypted control connection. Only one
   such control connection is supported at a time.
   
 */

#define NCOT_CONTROL_PACKET_LENGTH 512
#define NCOT_CONTROL_PACKET_IDENTIFIER "NCOT"

struct ncotcontrolpacket {
  char identifier[4];
  int length;
  char data[504];
};


/* returns 1 if packet has an valid identifier and the length value
   makes any sense.
*/

int ncot_control_packet_validate(struct ncotcontrolpacket *packet);

#endif
