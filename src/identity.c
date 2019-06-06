#include "identity.h"

struct ncot_identity*
ncot_identity_new()
{
	struct ncot_identity *identity;
	identity = calloc(1, sizeof(struct ncot_identity));
	return identity;
}

void
ncot_identity_init(struct ncot_identity *identity) {
	if (identity) {
		uuid_create(&identity->uuid);
		uuid_make(identity->uuid, UUID_MAKE_V1);
	} else {
		NCOT_LOG_WARNING("Invalid identity passed to ncot_identity_init\n");
	}
}

void
ncot_identity_free(struct ncot_identity **pidentity) {
	struct ncot_identity *identity;
	if (pidentity) {
		identity = *pidentity;
		if (identity) {
			if (identity->uuid) uuid_destroy(identity->uuid);
			free(identity);
			*pidentity = NULL;
		} else
			NCOT_LOG_ERROR("Invalid ncot_identity\n");
	} else
		NCOT_LOG_ERROR("Invalid argument (*identity)\n");
}

