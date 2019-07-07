#include <stdlib.h>
#include <check.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

/*#include "../src/config.h"
#include "../src/helper.h"
*/

#include "../src/connection.h"
#include "../src/log.h"
#include "../src/ncot.h"
#include "../src/context.h"
#include "../src/init.h"
#include "../src/select.h"
#include "../src/policy.h"
#include "../src/ring.h"

#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))

void setup()
{
}

void teardown()
{
}

#define NCOT_READ_BUFLEN 128

START_TEST (test_ring_context)
{
	struct ncot_context *context;
	struct ncot_policy *policy1;
	struct ncot_policy *policy2;
	struct ncot_ring_context *ringcontext;

	ncot_init();
	context = ncot_context_new();
	ncot_log_set_logfile("test_ringcontext.log");

	ringcontext = ncot_ring_context_new();
	ck_assert(ringcontext != NULL);

	policy1 = ncot_policy_new();
	policy2 = ncot_policy_new();
	ncot_policy_set_brief(policy1, "Only user with real names");
	ncot_policy_set_category(policy1, "Authenticity");
	ncot_policy_set_text(policy1, "This policy is intended for use only if you want to make sure the user interact under their real names and identity.");
	ncot_policy_set_brief(policy2, "Only user with other real names");
	ncot_policy_set_category(policy2, "Authenticity");
	ncot_policy_set_text(policy2, "This other policy is intended for use only if you want to make sure the user interact under their real names and identity.");

	ncot_ring_context_add_policy(ringcontext, policy1);
	ck_assert(ringcontext->policies != NULL);
	ncot_ring_context_add_policy(ringcontext, policy2);

	ncot_ring_context_free(&ringcontext);
	ck_assert(ringcontext == NULL);

	ncot_context_free(&context);
	ncot_done();
}
END_TEST

Suite * helper_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Ring Context");

	/* Core test case */
	tc_core = tcase_create("Core");
	tcase_add_unchecked_fixture(tc_core, setup, teardown);
	tcase_add_test(tc_core, test_ring_context);
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
