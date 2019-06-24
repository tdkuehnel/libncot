#include <stdlib.h>
#include <check.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/time.h>

/*#include "../src/config.h"
#include "../src/helper.h"
*/

#define DEBUG 0
#include "../src/debug.h"
#include "../src/connection.h"
#include "../src/log.h"
#include "../src/ncot.h"
#include "../src/context.h"
#include "../src/node.h"
#include "../src/init.h"
#include "../src/select.h"
#include "../src/identity.h"

#include <uuid.h>

#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))

#define PIDFILE_NAME_TEST_CONTEXT "context_ncotd.pid"

void setup()
{
}

void teardown()
{
}

#define NCOT_JSON_GOODFILE "context.json"
#define NCOT_JSON_BADFILE "contextbad.json"
#define NCOT_JSON_OUTPUT "context_output.json"
#define NCOT_UUID0 "725f0b14-95f2-11e9-8e62-0015f2f34329"
#define NCOT_UUID1 "977de3c6-939e-11e9-ba7a-0015f2f34329"
#define NCOT_UUID2 "bbb7c2ac-939e-11e9-afe9-0015f2f34329"
#define NCOT_UUID_IDENTITY "3d0fc356-9654-11e9-aa10-0015f2f34329"

START_TEST (test_context)
{
	struct ncot_context *context;
	int ret;
	char *uuidstring = NULL;
	size_t stringlen = UUID_LEN_STR;
	ncot_init();
	ncot_log_set_logfile("test_context.log");

	context = ncot_context_new();
	ck_assert(context != NULL);
	ret = ncot_context_init_from_file(context, NCOT_JSON_BADFILE);
	ck_assert(ret != NCOT_SUCCESS);
	ncot_context_free(&context);

	context = ncot_context_new();
	ck_assert(context != NULL);
	ret = ncot_context_init_from_file(context, NCOT_JSON_GOODFILE);
	ck_assert(ret == NCOT_SUCCESS);
	ck_assert(context->uuid != NULL);
	ret = uuid_export(context->uuid, UUID_FMT_STR, &uuidstring, NULL);
	ck_assert(ret == UUID_RC_OK);
	ck_assert_str_eq(NCOT_UUID0, uuidstring);

	ck_assert(context->identity != NULL);
	free(uuidstring);
	uuidstring=NULL;
	ret = uuid_export(context->identity->uuid, UUID_FMT_STR, &uuidstring, NULL);
	ck_assert(ret == UUID_RC_OK);
	ck_assert_str_eq(NCOT_UUID_IDENTITY, uuidstring);

	context->arguments->config_file = NCOT_JSON_OUTPUT;
	ncot_context_free(&context);

	ncot_done();
}
END_TEST


Suite * helper_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Context");

	/* Core test case */
	tc_core = tcase_create("Core");
	tcase_add_unchecked_fixture(tc_core, setup, teardown);
	tcase_set_timeout(tc_core, 4);
	/* The simple test is disabled because ncot_connection_connect
	 * now blocks because of the GnuTLS handshake. */
	/*tcase_add_test(tc_core, test_connection_simple);*/
	tcase_add_test(tc_core, test_context);
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
