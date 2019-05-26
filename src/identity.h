#ifndef _NCOT_IDENTITY_H_
#define _NCOT_IDENTITY_H_

#include <uuid.h>

/* Basic identitiy stuff. It is not clear if it is needed at
 * all. Maybe we can abstract the user away. :-) Needs rework as it
 * still uses typedefs. */

typedef struct ncot_identity_t {
  uuid_t *uuid;
} ncot_identity_t;

ncot_identity_t *ncot_identity_new();
void ncot_identity_free(ncot_identity_t **pidentity);
void ncot_identity_init(ncot_identity_t *identity);

#endif
