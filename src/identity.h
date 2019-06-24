#ifndef _NCOT_IDENTITY_H_
#define _NCOT_IDENTITY_H_

#include <uuid.h>
#include <json-c/json.h>

/* Basic identitiy stuff. It is not clear if it is needed at
 * all. Maybe we can abstract the user away. :-) Needs rework as it
 * still uses typedefs. */

/* After some thoughts we came to the point that identities are
   important. We follow the mantra "The data is yours, and you have
   full control over your data.", so if one wishes he can stay
   anonymous with as few public visible data as possible, or fullblown
   exhibit everthing you can, its the users choice. We need to provide
   a way so the people can find out by themselves what is best for
   them.
*/

/* Anyway, an identity is connected to the nodes it holds, an so in a
 * ring of trust, every identity is known to the other
 * identieties/nodes in the same ring. The messages that pass over
 * your node from one ring to another is something that is allways
 * traceable back to you. When you let spam pass, its you who gets
 * excluded from the ring when the ring policy says NO SPAM.
*/

struct ncot_identity;
struct ncot_identity {
	/* We need to distinguish identities */
	uuid_t *uuid;
	/* For the beginning an identity has two simple properties */
	/* Name of the identity */
	char name[256];
	/* Avatar, may be ASCII art to display on tty */
	char avatar[2048];
	/* We make this listable as we may need to cope with the
	 * public part of identities from peers */
	struct ncot_identity *next;
	/* Somehow represent the public/private credentials involved
	 * of an identity */
	/* struct ncot_identity_credentials credentials; */
	struct json_object *json;
};

struct ncot_identity *ncot_identity_new();
struct ncot_identity* ncot_identity_new_from_json(struct json_object *jsonobj);
void ncot_identity_free(struct ncot_identity **pidentity);
void ncot_identity_init(struct ncot_identity *identity);
void ncot_identity_save(struct ncot_identity *identity, struct json_object *parent);
#endif
