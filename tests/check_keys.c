#include <stdlib.h>
#include <check.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <json-c/json.h>
#include <libssh/libssh.h>

#include "../src/utlist.h"
#include "../src/node.h"
#include "../src/connection.h"
#include "../src/log.h"
#include "../src/ncot.h"
#include "../src/context.h"
#include "../src/init.h"
#include "../src/select.h"
#include "../src/keys.h"
#include "../src/ssh.h"
#include "../src/error.h"

#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))
#define PIDFILE_NAME_1 "ncotd1.pid"

void setup()
{
}

void teardown()
{
}

struct ncot_context*
new_context()
{
	struct ncot_context *context;
	context = ncot_context_new();
	ncot_context_init(context);
	return context;
}

START_TEST (test_keys)
{
	struct ncot_ssh_keypair *keypair;
	struct ncot_ssh_keyset *keyset;
	int r;

	ncot_init();
	ncot_log_set_logfile("test_keys.log");
	NCOT_LOG_INFO("CHECK KEYS STARTS HERE\n");
	keypair = ncot_ssh_keypair_new();
	ck_assert(keypair != NULL);
	r = ncot_ssh_keypair_init(keypair, NCOT_SSH_KEYTYPE_RSA);
	ck_assert(r == NCOT_OK);
	ck_assert(ssh_key_type(keypair->key) == SSH_KEYTYPE_RSA);
	ck_assert(keypair->type == NCOT_SSH_KEYTYPE_RSA);
	ncot_ssh_keypair_free(&keypair);

	keypair = ncot_ssh_keypair_new();
	ck_assert(keypair != NULL);
	r = ncot_ssh_keypair_init(keypair, NCOT_SSH_KEYTYPE_ECDSA_P256);
	ck_assert(r == NCOT_OK);
	ck_assert(ssh_key_type(keypair->key) == SSH_KEYTYPE_ECDSA_P256);
	ck_assert(keypair->type == NCOT_SSH_KEYTYPE_ECDSA_P256);
	ncot_ssh_keypair_free(&keypair);

	keypair = ncot_ssh_keypair_new();
	ck_assert(keypair != NULL);
	r = ncot_ssh_keypair_init(keypair, NCOT_SSH_KEYTYPE_ED25519);
	ck_assert(r == NCOT_OK);
	ck_assert(ssh_key_type(keypair->key) == SSH_KEYTYPE_ED25519);
	ck_assert(keypair->type == NCOT_SSH_KEYTYPE_ED25519);
	ncot_ssh_keypair_free(&keypair);
	ck_assert(keypair == NULL);

	keyset = ncot_ssh_keyset_new();
	ncot_ssh_keyset_init(keyset, NCOT_SSH_KEYTYPE_ECDSA_P256);
	ck_assert(ncot_ssh_keyset_has_keytype(keyset, NCOT_SSH_KEYTYPE_ECDSA_P256));
	ck_assert(!ncot_ssh_keyset_has_keytype(keyset, NCOT_SSH_KEYTYPE_RSA));
	ck_assert(!ncot_ssh_keyset_has_keytype(keyset, NCOT_SSH_KEYTYPE_ED25519));
	ncot_ssh_keyset_free(&keyset);

	keyset = ncot_ssh_keyset_new();
	ncot_ssh_keyset_init(keyset, NCOT_SSH_KEYTYPE_RSA|NCOT_SSH_KEYTYPE_ECDSA_P256|NCOT_SSH_KEYTYPE_ED25519);
	ck_assert(ncot_ssh_keyset_has_keytype(keyset, NCOT_SSH_KEYTYPE_ECDSA_P256));
	ck_assert(ncot_ssh_keyset_has_keytype(keyset, NCOT_SSH_KEYTYPE_RSA));
	ck_assert(ncot_ssh_keyset_has_keytype(keyset, NCOT_SSH_KEYTYPE_ED25519));
	ncot_ssh_keyset_free(&keyset);

	keyset = ncot_ssh_keyset_new();
	ck_assert(!ncot_ssh_keyset_has_keytype(keyset, NCOT_SSH_KEYTYPE_RSA));
	r = ncot_ssh_keyset_generate_key(keyset, NCOT_SSH_KEYTYPE_RSA);
	ck_assert(r == NCOT_OK);
	ck_assert(ncot_ssh_keyset_has_keytype(keyset, NCOT_SSH_KEYTYPE_RSA));
	r = ncot_ssh_keyset_generate_key(keyset, NCOT_SSH_KEYTYPE_RSA);
	ck_assert(r == NCOT_ERROR);
	ck_assert(ncot_ssh_keyset_has_keytype(keyset, NCOT_SSH_KEYTYPE_RSA));
	ncot_ssh_keyset_free(&keyset);

	NCOT_LOG_INFO("CHECK KEYS ENDS HERE\n");
	ncot_done();
}
END_TEST

START_TEST (test_keyset)
{
}
END_TEST

Suite * helper_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Keys");

	/* Core test case */
	tc_core = tcase_create("Core");
	tcase_add_checked_fixture(tc_core, setup, teardown);

	tcase_add_test(tc_core, test_keys);
	suite_add_tcase(s, tc_core);
	return s;
}

int main(void)
{
	int number_failed;
	Suite *s;
	SRunner *sr;

	s = helper_suite();
	sr = srunner_create(s);
	srunner_set_fork_status (sr, CK_FORK);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
