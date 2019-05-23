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

#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))

void setup()
{
}

void teardown()
{
	struct stat pidfilestat;
	printf("teardown\n");
	if (stat("ncotd1.pid", &pidfilestat) == 0) {
		printf("executing kill by pid\n");
		system("cat ncotd1.pid | xargs kill");
	}
}

/* Every test gets its own set of port numbers to avoid side
 * effects */

#define TEST_CONNECTION_SIMPLE_CLIENT_PORT  24003
#define TEST_CONNECTION_SIMPLE_SERVER_PORT  "24003"
#define TESTADDRESS_STRING "127.0.0.1"

START_TEST (test_connection_simple)
{
	struct ncot_connection *conn1;
	struct ncot_connection *conn2;
	struct ncot_context *context;
	int ret;

	ncot_init();
	context = ncot_context_new();

	ncot_log_set_logfile("test_connection_simple.log");

	conn1 = NULL;

	conn1 = ncot_connection_new();
	ck_assert(conn1 != NULL);

	ncot_connection_init(conn1, NCOT_CONN_CONTROL);

	ret = ncot_connection_listen(context, conn1, TEST_CONNECTION_SIMPLE_CLIENT_PORT);
	ck_assert_int_eq(ret, 0);

	conn2 = ncot_connection_new();
	ncot_connection_init(conn2, NCOT_CONN_CONTROL);

	ret = ncot_connection_connect(context, conn2, TEST_CONNECTION_SIMPLE_SERVER_PORT, TESTADDRESS_STRING);
	ck_assert_int_eq(ret, 0);

	ncot_connection_free(&conn1);
	ncot_connection_free(&conn2);

	ck_assert(conn1 == NULL);

	ncot_context_free(&context);
	ncot_done();
}
END_TEST

#define TESTPORT_GOOD  "24002"
#define TESTPORT_BAD  "24001"
START_TEST (test_connection_daemon)
{
	struct ncot_connection *conn1;
	struct ncot_connection *conn2;
	struct ncot_context *context;

	int ret;
	int i;

	i = system("../src/ncotd -d --pidfile=ncotd1.pid --logfile=test_connection_daemon-ncotd1.log");

	ck_assert(i == 0);

	sleep(1);
	ncot_init();
	ncot_log_set_logfile("test_connection_daemon.log");
	context = ncot_context_new();

	conn2 = ncot_connection_new();
	ncot_connection_init(conn2, NCOT_CONN_CONTROL);

	/* Try to connect to an unreachable port */
	ret = ncot_connection_connect(context, conn2, TESTPORT_BAD, TESTADDRESS_STRING);
 	ck_assert_int_eq(ret, 1);

	ret = ncot_connection_connect(context, conn2, TESTPORT_GOOD, TESTADDRESS_STRING);
	ck_assert_int_eq(ret, 0);

	ncot_connection_free(&conn2);

	ck_assert(conn1 == NULL);

	ncot_context_free(&context);
	ncot_done();

	/* We need to sleep here for a while to see in the log files
	 * weather the pselect loops run away, until we find a way to
	 * check against that with a ck_assert statement */
	sleep(1);
	i = system("cat ncotd1.pid | xargs kill");
	ck_assert(i == 0);
}
END_TEST


Suite * helper_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Connection");

	/* Core test case */
	tc_core = tcase_create("Core");
	tcase_add_unchecked_fixture(tc_core, setup, teardown);

	tcase_add_test(tc_core, test_connection_simple);
	tcase_add_test(tc_core, test_connection_daemon);
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
