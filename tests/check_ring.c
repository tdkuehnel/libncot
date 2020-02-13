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

#define PID_FILE_DAEMON_1 "ncotd_01.pid"
#define PID_FILE_DAEMON_2 "ncotd_02.pid"
#define PID_FILE_DAEMON_3 "ncotd_03.pid"
#define CONFIG_FILE_DAEMON_1 "config_daemon_01.json"
#define CONFIG_FILE_DAEMON_2 "config_daemon_02.json"
#define CONFIG_FILE_DAEMON_3 "config_daemon_03.json"
#define LOG_FILE_DAEMON_1 "test_ring_daemon_01.log"
#define LOG_FILE_DAEMON_2 "test_ring_daemon_02.log"
#define LOG_FILE_DAEMON_3 "test_ring_daemon_03.log"
#define PORT_DAEMON_1 "24001"
#define PORT_DAEMON_2 "24002"
#define PORT_DAEMON_3 "24003"

void teardown()
{
	/* Let our teardown routine take care of dangling daemons
	 * after failed tests */
	struct stat filestat;
	int i;
	i = stat(PID_FILE_DAEMON_3, &filestat);
	if (i== 0) system("cat " PID_FILE_DAEMON_3 " | xargs kill");
	i = stat(PID_FILE_DAEMON_2, &filestat);
	if (i== 0) system("cat " PID_FILE_DAEMON_2 " | xargs kill");
	i = stat(PID_FILE_DAEMON_1, &filestat);
	if (i== 0) system("cat " PID_FILE_DAEMON_1 " | xargs kill");

}

void
test_ring_cleanup()
{
	struct stat filestat;
	int i;
	i = stat(CONFIG_FILE_DAEMON_1, &filestat);
	if (i == 0) unlink(CONFIG_FILE_DAEMON_1);
	i = stat(CONFIG_FILE_DAEMON_2, &filestat);
	if (i == 0) unlink(CONFIG_FILE_DAEMON_2);
	i = stat(CONFIG_FILE_DAEMON_3, &filestat);
	if (i == 0) unlink(CONFIG_FILE_DAEMON_3);
	i = stat(PID_FILE_DAEMON_1, &filestat);
	if (i == 0) unlink(PID_FILE_DAEMON_1);
	i = stat(PID_FILE_DAEMON_2, &filestat);
	if (i == 0) unlink(PID_FILE_DAEMON_2);
	i = stat(PID_FILE_DAEMON_3, &filestat);
	if (i == 0) unlink(PID_FILE_DAEMON_3);
	i = stat(PID_FILE_DAEMON_3, &filestat);
	if (i== 0) system("cat " PID_FILE_DAEMON_3 " | xargs kill");
	i = stat(PID_FILE_DAEMON_2, &filestat);
	if (i== 0) system("cat " PID_FILE_DAEMON_2 " | xargs kill");
	i = stat(PID_FILE_DAEMON_1, &filestat);
	if (i== 0) system("cat " PID_FILE_DAEMON_1 " | xargs kill");
}

START_TEST (test_ring)
{
	struct ncot_context *context;
	int i;
	ncot_init(4);
	ncot_log_set_logfile("test_ring.log");
	NCOT_LOG_INFO("TEST_RING START\n");
	context = ncot_context_new();
	ncot_context_init(context);

	/* Clean up artifacts from failing tests */
	test_ring_cleanup();
	/* Let's start some daemons .. */
	i = system("../src/ncot -d --port="PORT_DAEMON_1" --pidfile="PID_FILE_DAEMON_1" --logfile="LOG_FILE_DAEMON_1" --configfile="CONFIG_FILE_DAEMON_1);
	ck_assert(i == 0);
	i = system("../src/ncot -d --port="PORT_DAEMON_2" --pidfile="PID_FILE_DAEMON_2" --logfile="LOG_FILE_DAEMON_2" --configfile="CONFIG_FILE_DAEMON_2);
	ck_assert(i == 0);
	i = system("../src/ncot -d --port="PORT_DAEMON_3" --pidfile="PID_FILE_DAEMON_3" --logfile="LOG_FILE_DAEMON_3" --configfile="CONFIG_FILE_DAEMON_3);
	ck_assert(i == 0);

	sleep(1);

	ncot_context_free(&context);
	NCOT_LOG_INFO("TEST_RING END\n");
	ncot_log_done();
	ncot_done();
}
END_TEST

Suite * helper_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Ring");

	/* Core test case */
	tc_core = tcase_create("Core");
	tcase_set_timeout(tc_core, 12);
	tcase_add_unchecked_fixture(tc_core, setup, teardown);
	tcase_add_test(tc_core, test_ring_context);
	tcase_add_test(tc_core, test_ring);
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
