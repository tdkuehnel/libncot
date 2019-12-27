#include <stdlib.h>
#include <check.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <json-c/json.h>
#include <libssh/libssh.h>
#include <uuid.h>

#include "../src/utlist.h"
#include "../src/node.h"
#include "../src/connection.h"
#include "../src/log.h"
#include "../src/ncot.h"
#include "../src/context.h"
#include "../src/init.h"
#include "../src/select.h"
#include "../src/keys.h"
#include "../src/db.h"
#include "../src/error.h"

#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))
#define PIDFILE_NAME_1 "ncotd1.pid"

void setup()
{
	system("rm -rf /tmp/.ncot");
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
	context->arguments = calloc(1, sizeof(struct ncot_arguments));
	context->arguments->ncot_dir = "/tmp/.ncot";
	return context;
}

START_TEST (test_db)
{

	struct ssh_key_struct *pkey;
	struct ncot_node *node;
	struct ncot_context *context;
	char *string =  NULL;
	char buf[2048];
	char buf2[2048];
	struct stat dstat;
	int r;

	ncot_init();
	ncot_log_set_logfile("test_db.log");
	NCOT_LOG_INFO("CHECK DB STARTS HERE\n");

	ncot_db_init();
	node = NULL;
	node = ncot_node_new();
	ncot_node_init(node);
	ncot_ssh_keyset_init(node->keyset, NCOT_SSH_KEYTYPE_RSA|NCOT_SSH_KEYTYPE_ECDSA_P256|NCOT_SSH_KEYTYPE_ED25519);
	context = new_context();
	NCOT_LOG_INFO("Mark 0\n");
	r = ncot_db_node_save_pkeys(context, node);
	ck_assert(r == NCOT_OK);
	uuid_export(node->uuid, UUID_FMT_STR, &string, NULL);
	ck_assert(string != NULL);

	snprintf((char*)&buf, 2048, "/tmp/.ncot/%s", string);
	ck_assert(stat((char*)&buf, &dstat) == 0);
	snprintf((char*)&buf2, 2048, "/tmp/.ncot/%s/id_rsa", string);
	ck_assert(stat((char*)&buf2, &dstat) == 0);
	snprintf((char*)&buf2, 2048, "/tmp/.ncot/%s/id_ecdsa", string);
	ck_assert(stat((char*)&buf2, &dstat) == 0);
	snprintf((char*)&buf2, 2048, "/tmp/.ncot/%s/id_ed25519", string);
	ck_assert(stat((char*)&buf2, &dstat) == 0);
	snprintf((char*)&buf2, 2048, "/tmp/.ncot/%s/id_rsa.pub", string);
	ck_assert(stat((char*)&buf2, &dstat) == 0);
	snprintf((char*)&buf2, 2048, "/tmp/.ncot/%s/id_ecdsa.pub", string);
	ck_assert(stat((char*)&buf2, &dstat) == 0);
	snprintf((char*)&buf2, 2048, "/tmp/.ncot/%s/id_ed25519.pub", string);
	ck_assert(stat((char*)&buf2, &dstat) == 0);


	ncot_node_free(&node);
	ck_assert(node == NULL);

	ncot_context_free(&context);
	ncot_done();
}
END_TEST

Suite * helper_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Db");

	/* Core test case */
	tc_core = tcase_create("Core");
	tcase_add_checked_fixture(tc_core, setup, teardown);

	tcase_add_test(tc_core, test_db);
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
