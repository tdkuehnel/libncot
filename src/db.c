#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "error.h"
#include "db.h"

ncot_db_node_load_key_function ncot_db_node_load_key_function_pointer = NULL;
ncot_db_node_load_pkey_function ncot_db_node_load_pkey_function_pointer = NULL;
ncot_db_node_save_keys_function ncot_db_node_save_keys_function_pointer = NULL;

void
ncot_db_init()
{
	ncot_db_node_load_key_function_pointer = &ncot_db_node_load_key_file;
	ncot_db_node_load_pkey_function_pointer = &ncot_db_node_load_pkey_file;
	ncot_db_node_save_keys_function_pointer = &ncot_db_node_save_keys_file;
}

/** general calling function interface */
int
ncot_db_node_load_key(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype type)
{
	if (!ncot_db_node_load_key_function_pointer) ncot_db_init();
	return (*ncot_db_node_load_key_function_pointer)(context, node, type);
}

int
ncot_db_node_load_pkey(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype type)
{
	if (!ncot_db_node_load_key_function_pointer) ncot_db_init();
	return (*ncot_db_node_load_pkey_function_pointer)(context, node, type);
}

int
ncot_db_node_save_keys(struct ncot_context *context, struct ncot_node *node)
{
	if (!ncot_db_node_load_key_function_pointer) ncot_db_init();
	return (*ncot_db_node_save_keys_function_pointer)(context, node);
}


/** json implementation */
int
ncot_db_node_load_key_json(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype type)
{
}

int
ncot_db_node_load_pkey_json(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype type)
{
}

int
ncot_db_node_save_keys_json(struct ncot_context *context, struct ncot_node *node)
{
}

/** plain file implementation with subdir per node */
int
ncot_db_node_load_key_file(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype type)
{
	char *uuidstring =  NULL;
	char dirpath[2048] = {'\0'};
	char filepath[2048] = {'\0'};
	struct stat dstat;
	int r;
	int i;

	if (!context || !node) {
		NCOT_LOG_ERROR("ncot_db_node_load_key_file: invalid parameters\n");
		return NCOT_ERROR;
	}
	if (!node->keyset) {
		NCOT_LOG_ERROR("ncot_db_node_load_key_file: node without keyset\n");
		return NCOT_ERROR;
	}
	if (!ncot_ssh_keyset_has_keytype(node->keyset, type)) {
		for (i=0; i<NCOT_SSH_KEYSET_NUMS; i++) if (node->keyset->keypairs[i] == NULL) break;
		if (i == NCOT_SSH_KEYSET_NUMS && node->keyset->keypairs[i] != NULL) {
			NCOT_LOG_ERROR("ncot_db_node_load_key_file: keyset of node has already %d keys (max) in it.\n", NCOT_SSH_KEYSET_NUMS);
			return NCOT_ERROR;
		} else {
			node->keyset->keypairs[i] = ncot_ssh_keypair_new();
			if (!node->keyset->keypairs[i]) return NCOT_ERROR;
			node->keyset->keypairs[i]->type = type;
		}
	} else {
		for (i=0; i<NCOT_SSH_KEYSET_NUMS; i++) if (node->keyset->keypairs[i]->type == type) break;
		if (i == NCOT_SSH_KEYSET_NUMS && node->keyset->keypairs[i]->type != type) {
			NCOT_LOG_ERROR("ncot_db_node_load_key_file: keyset inconsistency (should never happen)\n", NCOT_SSH_KEYSET_NUMS);
			return NCOT_ERROR;
		}
	}
	/* We have a keypair of type type where i is the index of */
	if (node->keyset->keypairs[i]->key) {
		NCOT_LOG_WARNING("ncot_db_node_load_key_file: node has keypair of type %s with private key already in keyset, overloading\n", ncot_ssh_keytype_to_char(type));
		ssh_key_free(node->keyset->keypairs[i]->key);
	}
	uuid_export(node->uuid, UUID_FMT_STR, &uuidstring, NULL);
	snprintf((char*)&dirpath, 2048, "%s/%s", context->arguments->ncot_dir, uuidstring);
	switch(type) {
	case NCOT_SSH_KEYTYPE_RSA:
		r = snprintf((char*)&filepath, 2048, "%s/%s/%s", context->arguments->ncot_dir, uuidstring, "id_rsa");
		break;
	case NCOT_SSH_KEYTYPE_ECDSA_P256:
		r = snprintf((char*)&filepath, 2048, "%s/%s/%s", context->arguments->ncot_dir, uuidstring, "id_ecdsa_p256");
		break;
	case NCOT_SSH_KEYTYPE_ED25519:
		r = snprintf((char*)&filepath, 2048, "%s/%s/%s", context->arguments->ncot_dir, uuidstring, "id_ed25519");
		break;
	default:
		NCOT_LOG_ERROR("ncot_db_node_load_key_file: unknown keytype\n");
		return NCOT_ERROR;
	}
	r = ssh_pki_import_privkey_file((char*)filepath, context->arguments->keypass, NULL, NULL, &node->keyset->keypairs[i]->key);
	if (r != SSH_OK) {
		NCOT_LOG_ERROR("ncot_db_node_load_key_file: unable to load key from file: %s\n", filepath);
		return NCOT_ERROR;
	}
	NCOT_LOG_INFO("ncot_db_node_load_key_file: private key of type %s loaded from file %s.\n", ncot_ssh_keytype_to_char(type),filepath);
	return NCOT_OK;
}

int
ncot_db_node_load_pkey_file(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype type)
{
	char *uuidstring =  NULL;
	char dirpath[2048] = {'\0'};
	char filepath[2048] = {'\0'};
	struct stat dstat;
	int r;
	int i;

	if (!context || !node) {
		NCOT_LOG_ERROR("ncot_db_node_load_pkey_file: invalid parameters\n");
		return NCOT_ERROR;
	}
	if (!node->keyset) {
		NCOT_LOG_ERROR("ncot_db_node_load_pkey_file: node without keyset\n");
		return NCOT_ERROR;
	}
	if (!ncot_ssh_keyset_has_keytype(node->keyset, type)) {
		for (i=0; i<NCOT_SSH_KEYSET_NUMS; i++) if (node->keyset->keypairs[i] == NULL) break;
		if (i == NCOT_SSH_KEYSET_NUMS && node->keyset->keypairs[i] != NULL) {
			NCOT_LOG_ERROR("ncot_db_node_load_key_file: keyset of node has already %d keys (max) in it.\n", NCOT_SSH_KEYSET_NUMS);
			return NCOT_ERROR;
		} else {
			node->keyset->keypairs[i] = ncot_ssh_keypair_new();
			if (!node->keyset->keypairs[i]) return NCOT_ERROR;
			node->keyset->keypairs[i]->type = type;
		}
	} else {
		for (i=0; i<NCOT_SSH_KEYSET_NUMS; i++) if (node->keyset->keypairs[i]->type == type) break;
		if (i == NCOT_SSH_KEYSET_NUMS && node->keyset->keypairs[i]->type != type) {
			NCOT_LOG_ERROR("ncot_db_node_load_key_file: keyset inconsistency (should never happen)\n", NCOT_SSH_KEYSET_NUMS);
			return NCOT_ERROR;
		}
	}
	if (node->keyset->keypairs[i]->pkey) {
		NCOT_LOG_WARNING("ncot_db_node_load_pkey_file: node has keypair of type %s with public key already in keyset, overloading\n", ncot_ssh_keytype_to_char(type));
		ssh_key_free(node->keyset->keypairs[i]->pkey);
	}
	uuid_export(node->uuid, UUID_FMT_STR, &uuidstring, NULL);
	snprintf((char*)&dirpath, 2048, "%s/%s", context->arguments->ncot_dir, uuidstring);
	switch(type) {
	case NCOT_SSH_KEYTYPE_RSA:
		r = snprintf((char*)&filepath, 2048, "%s/%s/%s", context->arguments->ncot_dir, uuidstring, "id_rsa.pub");
		break;
	case NCOT_SSH_KEYTYPE_ECDSA_P256:
		r = snprintf((char*)&filepath, 2048, "%s/%s/%s", context->arguments->ncot_dir, uuidstring, "id_ecdsa_p256.pub");
		break;
	case NCOT_SSH_KEYTYPE_ED25519:
		r = snprintf((char*)&filepath, 2048, "%s/%s/%s", context->arguments->ncot_dir, uuidstring, "id_ed25519.pub");
		break;
	default:
		NCOT_LOG_ERROR("ncot_db_node_load_pkey_file: unknown keytype\n");
		return NCOT_ERROR;
	}
	r = ssh_pki_import_pubkey_file((char*)filepath, &node->keyset->keypairs[i]->pkey);
	if (r != SSH_OK) {
		NCOT_LOG_ERROR("ncot_db_node_load_pkey_file: unable to load pkey from file: %s.\n", filepath);
		return NCOT_ERROR;
	}
	NCOT_LOG_INFO("ncot_db_node_load_pkey_file: public key of type %s loaded from file %s.\n", ncot_ssh_keytype_to_char(type),filepath);
	return NCOT_OK;
}

/* Save all keys of a node to its files */
int
ncot_db_node_save_keys_file(struct ncot_context *context, struct ncot_node *node)
{
	char *uuidstring =  NULL;
	char dirpath[2048] = {'\0'};
	char filepath[2048] = {'\0'};
	struct stat dstat;
	int r;
	int i;
	int oldumask;

	if (!context || !node) {
		NCOT_LOG_ERROR("ncot_db_node_save_pkeys_file: invalid parameters\n");
		return NCOT_ERROR;
	}
	if (!node->keyset) {
		NCOT_LOG_ERROR("ncot_db_node_save_pkeys_file: node without keyset\n");
		return NCOT_ERROR;
	}
	uuid_export(node->uuid, UUID_FMT_STR, &uuidstring, NULL);
	snprintf((char*)&dirpath, 2048, "%s/%s", context->arguments->ncot_dir, uuidstring);
	r = stat(context->arguments->ncot_dir, &dstat);
	if (r != 0) {
		r = mkdir(context->arguments->ncot_dir, S_IRWXU|S_IRGRP|S_IXGRP);
		if (r != 0) {
			NCOT_LOG_ERROR("ncot_db_node_save_pkeys_file: cannot create dir %s\n", context->arguments->ncot_dir);
		} else {
			NCOT_LOG_INFO("ncot_db_node_save_pkeys_file: directory %s created\n", context->arguments->ncot_dir);
		}
	}
	r = stat((char*)&dirpath, &dstat);
	if (r != 0) {
		r = mkdir((char*)&dirpath, S_IRWXU|S_IRGRP|S_IXGRP);
		if (r != 0) {
			NCOT_LOG_ERROR("ncot_db_node_save_pkeys_file: cannot create dir %s\n", dirpath);
		} else {
			NCOT_LOG_INFO("ncot_db_node_save_pkeys_file: directory %s created\n", dirpath);
		}
	}
	oldumask = umask(0077);
	for (i = 0; i < NCOT_SSH_KEYSET_NUMS; i++) {
		if (node->keyset->keypairs[i]) {
			switch(node->keyset->keypairs[i]->type) {
			case NCOT_SSH_KEYTYPE_RSA:
				r = snprintf((char*)&dirpath, 2048, "%s/%s/%s", context->arguments->ncot_dir, uuidstring, "id_rsa");
				if (r >= 0) dirpath[r] = '\0';
				r = ssh_pki_export_privkey_file(node->keyset->keypairs[i]->key,
								context->arguments->keypass,
								NULL, NULL,
								(char*) &dirpath);
				if (!node->keyset->keypairs[i]->pkey)
					ssh_pki_export_privkey_to_pubkey(node->keyset->keypairs[i]->key, &node->keyset->keypairs[i]->pkey);
				r = snprintf((char*)&dirpath, 2048, "%s/%s/%s", context->arguments->ncot_dir, uuidstring, "id_rsa.pub");
				if (r >= 0) dirpath[r] = '\0';
				r = ssh_pki_export_pubkey_file(node->keyset->keypairs[i]->pkey, (void*)&dirpath);
				break;
			case NCOT_SSH_KEYTYPE_ECDSA_P256:
 				r = snprintf((char*)&dirpath, 2048, "%s/%s/%s", context->arguments->ncot_dir, uuidstring, "id_ecdsa_p256");
				if (r >= 0) dirpath[r] = '\0';
				r = ssh_pki_export_privkey_file(node->keyset->keypairs[i]->key,
								context->arguments->keypass,
								NULL, NULL,
								(char*) &dirpath);
				if (!node->keyset->keypairs[i]->pkey)
					ssh_pki_export_privkey_to_pubkey(node->keyset->keypairs[i]->key, &node->keyset->keypairs[i]->pkey);
				r = snprintf((char*)&dirpath, 2048, "%s/%s/%s", context->arguments->ncot_dir, uuidstring, "id_ecdsa_p256.pub");
				if (r >= 0) dirpath[r] = '\0';
				r = ssh_pki_export_pubkey_file(node->keyset->keypairs[i]->pkey, (void*)&dirpath);
				break;
			case NCOT_SSH_KEYTYPE_ED25519:
				r = snprintf((char*)&dirpath, 2048, "%s/%s/%s", context->arguments->ncot_dir, uuidstring, "id_ed25519");
				if (r >= 0) dirpath[r] = '\0';
				r = ssh_pki_export_privkey_file(node->keyset->keypairs[i]->key,
								context->arguments->keypass,
								NULL, NULL,
								(char*) &dirpath);
				if (!node->keyset->keypairs[i]->pkey)
					ssh_pki_export_privkey_to_pubkey(node->keyset->keypairs[i]->key, &node->keyset->keypairs[i]->pkey);
				r = snprintf((char*)&dirpath, 2048, "%s/%s/%s", context->arguments->ncot_dir, uuidstring, "id_ed25519.pub");
				if (r >= 0) dirpath[r] = '\0';
				r = ssh_pki_export_pubkey_file(node->keyset->keypairs[i]->pkey, (void*)&dirpath);
				break;
			}
		}
	}
	umask(oldumask);
	NCOT_LOG_INFO("ncot_db_node_save_pkeys_file: end of function\n");
}

