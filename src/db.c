#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "error.h"
#include "db.h"

ncot_db_node_get_pkey_function ncot_db_node_get_pkey_function_pointer = NULL;
ncot_db_node_save_pkeys_function ncot_db_node_save_pkeys_function_pointer = NULL;

void
ncot_db_init()
{
	ncot_db_node_get_pkey_function_pointer = &ncot_db_node_get_pkey_file;
	ncot_db_node_save_pkeys_function_pointer = &ncot_db_node_save_pkeys_file;
}

/** general calling function interface */
struct ssh_key_struct*
ncot_db_node_get_pkey(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype keytype)
{
	return (*ncot_db_node_get_pkey_function_pointer)(context, node, keytype);
}

int
ncot_db_node_save_pkeys(struct ncot_context *context, struct ncot_node *node)
{
	return (*ncot_db_node_save_pkeys_function_pointer)(context, node);
}


/** json implementation */
struct ssh_key_struct*
ncot_db_node_get_pkey_json(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype keytype)
{
}

int
ncot_db_node_save_pkeys_json(struct ncot_context *context, struct ncot_node *node)
{
}

/** plain file implementation with subdir per node */
struct ssh_key_struct*
ncot_db_node_get_pkey_file(struct ncot_context *context, struct ncot_node *node, enum ncot_ssh_keytype keytype)
{
}

int
ncot_db_node_save_pkeys_file(struct ncot_context *context, struct ncot_node *node)
{
	char *string =  NULL;
	char buf[2048] = {'\0'};
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
	/* NCOT_LOG_INFO("ncot_db_node_save_pkeys_file: Mark 1\n"); */
	uuid_export(node->uuid, UUID_FMT_STR, &string, NULL);
	snprintf((char*)&buf, 2048, "%s/%s", context->arguments->ncot_dir, string);
	r = stat(context->arguments->ncot_dir, &dstat);
	if (r != 0) {
		r = mkdir(context->arguments->ncot_dir, S_IRWXU|S_IRGRP|S_IXGRP);
		if (r != 0) {
			NCOT_LOG_ERROR("ncot_db_node_save_pkeys_file: cannot create dir %s\n", context->arguments->ncot_dir);
		} else {
			NCOT_LOG_INFO("ncot_db_node_save_pkeys_file: directory %s created\n", context->arguments->ncot_dir);
		}
	}
	r = stat((char*)&buf, &dstat);
	if (r != 0) {
		r = mkdir((char*)&buf, S_IRWXU|S_IRGRP|S_IXGRP);
		if (r != 0) {
			NCOT_LOG_ERROR("ncot_db_node_save_pkeys_file: cannot create dir %s\n", buf);
		} else {
			NCOT_LOG_INFO("ncot_db_node_save_pkeys_file: directory %s created\n", buf);
		}
	}
	oldumask = umask(0077);
	for (i = 0; i < NCOT_SSH_KEYSET_NUMS; i++) {
		if (node->keyset->keypairs[i]) {
			switch(node->keyset->keypairs[i]->type) {
			case NCOT_SSH_KEYTYPE_RSA:
				r = snprintf((char*)&buf, 2048, "%s/%s/%s", context->arguments->ncot_dir, string, "id_rsa");
				if (r >= 0) buf[r] = '\0';
				r = ssh_pki_export_privkey_file(node->keyset->keypairs[i]->key,
								context->arguments->keypass,
								NULL, NULL,
								(char*) &buf);
				if (!node->keyset->keypairs[i]->pkey)
					ssh_pki_export_privkey_to_pubkey(node->keyset->keypairs[i]->key, &node->keyset->keypairs[i]->pkey);
				r = snprintf((char*)&buf, 2048, "%s/%s/%s", context->arguments->ncot_dir, string, "id_rsa.pub");
				if (r >= 0) buf[r] = '\0';
				r = ssh_pki_export_pubkey_file(node->keyset->keypairs[i]->pkey, (void*)&buf);
				break;
			case NCOT_SSH_KEYTYPE_ECDSA_P256:
 				r = snprintf((char*)&buf, 2048, "%s/%s/%s", context->arguments->ncot_dir, string, "id_ecdsa");
				if (r >= 0) buf[r] = '\0';
				r = ssh_pki_export_privkey_file(node->keyset->keypairs[i]->key,
								context->arguments->keypass,
								NULL, NULL,
								(char*) &buf);
				if (!node->keyset->keypairs[i]->pkey)
					ssh_pki_export_privkey_to_pubkey(node->keyset->keypairs[i]->key, &node->keyset->keypairs[i]->pkey);
				r = snprintf((char*)&buf, 2048, "%s/%s/%s", context->arguments->ncot_dir, string, "id_ecdsa.pub");
				if (r >= 0) buf[r] = '\0';
				r = ssh_pki_export_pubkey_file(node->keyset->keypairs[i]->pkey, (void*)&buf);
				break;
			case NCOT_SSH_KEYTYPE_ED25519:
				r = snprintf((char*)&buf, 2048, "%s/%s/%s", context->arguments->ncot_dir, string, "id_ed25519");
				if (r >= 0) buf[r] = '\0';
				r = ssh_pki_export_privkey_file(node->keyset->keypairs[i]->key,
								context->arguments->keypass,
								NULL, NULL,
								(char*) &buf);
				if (!node->keyset->keypairs[i]->pkey)
					ssh_pki_export_privkey_to_pubkey(node->keyset->keypairs[i]->key, &node->keyset->keypairs[i]->pkey);
				r = snprintf((char*)&buf, 2048, "%s/%s/%s", context->arguments->ncot_dir, string, "id_ed25519.pub");
				if (r >= 0) buf[r] = '\0';
				r = ssh_pki_export_pubkey_file(node->keyset->keypairs[i]->pkey, (void*)&buf);
				break;
			}
		}
	}
	umask(oldumask);
	NCOT_LOG_INFO("ncot_db_node_save_pkeys_file: end of function\n");
}

