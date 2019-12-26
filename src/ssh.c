#include "error.h"
#include "log.h"
#include "ssh.h"
#include "keys.h"

struct ncot_ssh_keypair*
ncot_ssh_keypair_new()
{
	struct ncot_ssh_keypair *keypair;
	keypair = calloc(1, sizeof(struct ncot_ssh_keypair));
	return keypair;
}

int
ncot_ssh_keypair_init(struct ncot_ssh_keypair *keypair, enum ncot_ssh_keytype type)
{
	int r1;
	int r2;
	switch(type) {
	case NCOT_SSH_KEYTYPE_RSA:
		if (!ssh_pki_generate(SSH_KEYTYPE_RSA, 1024, &keypair->key) == SSH_OK) {
			NCOT_LOG_ERROR("ncot_ssh_keypair_init: unable to generate key rsa\n");
			return NCOT_FAILURE;
		}
		if (!ssh_pki_export_privkey_to_pubkey(keypair->key, &keypair->pkey) == SSH_OK) {
			NCOT_LOG_ERROR("ncot_ssh_keypair_init: unable to derive pkey from key rsa\n");
			return NCOT_FAILURE;
		}
		keypair->type = type;
		break;
	case NCOT_SSH_KEYTYPE_ECDSA_P256:
		if (!ssh_pki_generate(SSH_KEYTYPE_ECDSA, 256, &keypair->key) == SSH_OK) {
			NCOT_LOG_ERROR("ncot_ssh_keypair_init: unable to generate key ECDSA_P256\n");
			return NCOT_FAILURE;
		}
		if (!ssh_pki_export_privkey_to_pubkey(keypair->key, &keypair->pkey) == SSH_OK) {
			NCOT_LOG_ERROR("ncot_ssh_keypair_init: unable to derive pkey from key ECDSA_P256\n");
			return NCOT_FAILURE;
		}
		keypair->type = type;
		break;
	case NCOT_SSH_KEYTYPE_ED25519:
		if (!ssh_pki_generate(SSH_KEYTYPE_ED25519, 0, &keypair->key) == SSH_OK) {
			NCOT_LOG_ERROR("ncot_ssh_keypair_init: unable to generate key ED25519\n");
			return NCOT_FAILURE;
		}
		if (!ssh_pki_export_privkey_to_pubkey(keypair->key, &keypair->pkey) == SSH_OK) {
			NCOT_LOG_ERROR("ncot_ssh_keypair_init: unable to derive pkey from key ED25519\n");
			return NCOT_FAILURE;
		}
		keypair->type = type;
		break;
	default:
		NCOT_LOG_ERROR("ncot_ssh_keypair_init: unsupported keytype\n");
		return NCOT_ERROR;
	}
	NCOT_LOG_INFO("ncot_ssh_keypair_init: generated %s keypair\n", ssh_key_type_to_char(ssh_key_type(keypair->key)));
	return NCOT_OK;
}

void
ncot_ssh_keypair_free(struct ncot_ssh_keypair **pkeypair)
{
	struct ncot_ssh_keypair *keypair;
	if (pkeypair) {
		keypair = *pkeypair;
		if (keypair) {
			if (keypair->pkey) ssh_key_free(keypair->pkey);
			if (keypair->key) ssh_key_free(keypair->key);
			free(keypair);
			*pkeypair = NULL;
		}
	}
}

/** keyset for libssh use */

struct ncot_ssh_keyset*
ncot_ssh_keyset_new()
{
	struct ncot_ssh_keyset *keyset;
	keyset = calloc(1, sizeof(struct ncot_ssh_keyset));
	return keyset;
}

int
ncot_ssh_keyset_has_keytype(struct ncot_ssh_keyset *keyset, enum ncot_ssh_keytype type)
{
	int i;
	for (i=0; i < NCOT_SSH_KEYSET_NUMS; i++) {
		if (keyset->keypairs[i]) {
			if (keyset->keypairs[i]->type == type) {
				return 1;
			}
		}
	}
}

int
ncot_ssh_keyset_init(struct ncot_ssh_keyset *keyset, int types)
{
	int i = 0;
	int r;
	if (!keyset) {
		NCOT_LOG_ERROR("ncot_ssh_keyset_init: invalid parameters keyset\n");
		return NCOT_ERROR;
	}
	if (keyset->keypairs[0] || keyset->keypairs[1] || keyset->keypairs[2] || types==0) {
		NCOT_LOG_ERROR("ncot_ssh_keyset_init: invalid parameters keypairs[x] or types\n");
		return NCOT_ERROR;
	}
	if (types & NCOT_SSH_KEYTYPE_RSA) {
		if (!ncot_ssh_keyset_has_keytype(keyset, NCOT_SSH_KEYTYPE_RSA)) {
			keyset->keypairs[i] = ncot_ssh_keypair_new();
			ncot_ssh_keypair_init(keyset->keypairs[i++], NCOT_SSH_KEYTYPE_RSA);
			NCOT_LOG_INFO("ncot_ssh_keyset_init: add RSA key to keyset \n");
		} else {
			NCOT_LOG_WARNING("ncot_ssh_keyset_init: keyset has keytype RSA already, skipping key generation\n");
		}
	}
	if (types & NCOT_SSH_KEYTYPE_ECDSA_P256) {
		if (!ncot_ssh_keyset_has_keytype(keyset, NCOT_SSH_KEYTYPE_ECDSA_P256)) {
			keyset->keypairs[i] = ncot_ssh_keypair_new();
			ncot_ssh_keypair_init(keyset->keypairs[i++], NCOT_SSH_KEYTYPE_ECDSA_P256);
			NCOT_LOG_INFO("ncot_ssh_keyset_init: add ECDSA_P256 key to keyset \n");
		} else {
			NCOT_LOG_WARNING("ncot_ssh_keyset_init: keyset has keytype ECDSA_P256 already, skipping key generation\n");
		}
	}
	/* TODO add missing ECDSA types */
	if (types & NCOT_SSH_KEYTYPE_ED25519) {
		if (!ncot_ssh_keyset_has_keytype(keyset, NCOT_SSH_KEYTYPE_ED25519)) {
			keyset->keypairs[i] = ncot_ssh_keypair_new();
			ncot_ssh_keypair_init(keyset->keypairs[i++], NCOT_SSH_KEYTYPE_ED25519);
			NCOT_LOG_INFO("ncot_ssh_keyset_init: add ED25519 key to keyset \n");
		} else {
			NCOT_LOG_WARNING("ncot_ssh_keyset_init: keyset has keytype ED25519 already, skipping key generation\n");
		}
	}
	if (i) NCOT_LOG_INFO("ncot_ssh_keyset_init: init keyset with %d keypairs\n", i);
}

void
ncot_ssh_keyset_free(struct ncot_ssh_keyset **pkeyset)
{
	struct ncot_ssh_keyset *keyset;
	if (pkeyset) {
		keyset = *pkeyset;
		if (keyset) {
			free(keyset);
			*pkeyset = NULL;
		}
	}
}


