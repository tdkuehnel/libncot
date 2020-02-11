#include <json-c/json.h>
#include "identity.h"
#include "log.h"

struct ncot_identity*
ncot_identity_new()
{
	struct ncot_identity *identity;
	identity = calloc(1, sizeof(struct ncot_identity));
	return identity;
}

struct ncot_identity*
ncot_identity_new_from_json(struct json_object *jsonobj)
{
	struct ncot_identity *identity;
	struct json_object *jsonvalue;
	const char *string;
	int ret;
	identity = calloc(1, sizeof(struct ncot_identity));
	if (!identity) return identity;
	uuid_create(&identity->uuid);
	/* First the uuid */
	ret = json_object_object_get_ex(jsonobj, "uuid", &jsonvalue);
	if (! ret) {
		NCOT_LOG_ERROR("ncot_identity_new_from_json:  no field name \"uuid\" in json\n");
		ncot_identity_free(&identity);
		return identity;
	}
	string = json_object_get_string(jsonvalue);
	ret = uuid_import(identity->uuid, UUID_FMT_STR, string, strlen(string));
	if (ret != UUID_RC_OK) {
		NCOT_LOG_ERROR("ncot_identity_new_from_json: error importing uuid from json\n");
		ncot_identity_free(&identity);
	}
	/* Next is name */
	ret = json_object_object_get_ex(jsonobj, "name", &jsonvalue);
	if (! ret) {
		NCOT_LOG_WARNING("ncot_identity_new_from_json:  no field name \"name\" in json\n");
	} else {
		string = json_object_get_string(jsonvalue);
		strncpy(identity->name, string, NCOT_IDENTITY_NAME_LENGTH);
		identity->name[NCOT_IDENTITY_NAME_LENGTH - 1] = '\0';
	}
	/* Avatar */
	ret = json_object_object_get_ex(jsonobj, "avatar", &jsonvalue);
	if (! ret) {
		NCOT_LOG_WARNING("ncot_identity_new_from_json:  no field name \"avatar\" in json\n");
	} else {
		string = json_object_get_string(jsonvalue);
		strncpy(identity->avatar, string, NCOT_IDENTITY_AVATAR_LENGTH);
		identity->avatar[NCOT_IDENTITY_AVATAR_LENGTH - 1] = '\0';
	}
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
ncot_identity_save(struct ncot_identity *identity, struct json_object *parent)
{
	int ret;
	char *string =  NULL;

	ret = uuid_export(identity->uuid, UUID_FMT_STR, &string, NULL);
	if (ret != UUID_RC_OK) {
		NCOT_LOG_ERROR("ncot_identity_save: unable to convert uuid, aborting save.\n");
		return;
	}
	identity->json = json_object_new_string(string);
	json_object_object_add_ex(parent, "uuid", identity->json, JSON_C_OBJECT_KEY_IS_CONSTANT);
	identity->json = json_object_new_string(identity->name);
	json_object_object_add_ex(parent, "name", identity->json, JSON_C_OBJECT_KEY_IS_CONSTANT);
	identity->json = json_object_new_string(identity->avatar);
	json_object_object_add_ex(parent, "avatar", identity->json, JSON_C_OBJECT_KEY_IS_CONSTANT);
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

