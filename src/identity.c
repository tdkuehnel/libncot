ncot_identity_t *ncot_identity_new()
{
	ncot_identity_t *identity;
	identity = calloc(1, sizeof(ncot_identity_t));
	return identity;
}

void ncot_identity_init(ncot_identity_t *identity) {
	if (identity) {
		uuid_create(&identity->uuid);
		uuid_make(identity->uuid, UUID_MAKE_V1);
	} else {
		NCOT_LOG_WARNING("Invalid identity passed to ncot_identity_init\n");
	}
}

void ncot_identity_free(ncot_identity_t **pidentity) {
	ncot_identity_t *identity;
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

