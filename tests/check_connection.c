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
#include "../src/init.h"
#include "../src/select.h"

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

void test_iterate_io()
{
}

#define TESTPORT_GOOD  "24002"
#define TESTPORT_BAD  "24001"
START_TEST (test_connection_daemon)
{
	struct ncot_connection *conn1;
	struct ncot_connection *conn2;
	struct ncot_context *context;

	const char *message = "message";
	const char *messageraw = "NCOT00.00.01TEST00messageraw";
	char *messagepointer;
	int ret;
	int i;
	int r;
	int highestfd;
	fd_set rfds, wfds;
	struct timeval  tv1, tv2;
	gettimeofday(&tv1, NULL);
	i = system("../src/ncotd -d --pidfile=ncotd1.pid --logfile=test_connection_daemon-ncotd1.log");
	gettimeofday(&tv2, NULL);
	printf ("Total time = %f seconds\n", (double) (tv2.tv_usec - tv1.tv_usec) / 1000000 + (double) (tv2.tv_sec - tv1.tv_sec));
	ck_assert(i == 0);

	sleep(1);
	gettimeofday(&tv1, NULL);
	ncot_init();
	ncot_log_set_logfile("test_connection_daemon.log");
	context = ncot_context_new();
	ncot_context_init(context);
	gettimeofday(&tv2, NULL);
	printf ("Total time = %f seconds\n", (double) (tv2.tv_usec - tv1.tv_usec) / 1000000 + (double) (tv2.tv_sec - tv1.tv_sec));

	gettimeofday(&tv1, NULL);
	conn2 = context->controlconnection;

	/* Try to connect to an unreachable port */
	ret = ncot_connection_connect(context, conn2, TESTPORT_BAD, TESTADDRESS_STRING);
 	ck_assert_int_eq(ret, 1);
	gettimeofday(&tv2, NULL);
	printf ("Total time = %f seconds\n", (double) (tv2.tv_usec - tv1.tv_usec) / 1000000 + (double) (tv2.tv_sec - tv1.tv_sec));

	gettimeofday(&tv1, NULL);
	ret = ncot_connection_connect(context, conn2, TESTPORT_GOOD, TESTADDRESS_STRING);
	ck_assert_int_eq(ret, 0);
	gettimeofday(&tv2, NULL);
	printf ("Total time = %f seconds\n", (double) (tv2.tv_usec - tv1.tv_usec) / 1000000 + (double) (tv2.tv_sec - tv1.tv_sec));

	gettimeofday(&tv1, NULL);
	ret = ncot_connection_authenticate_server(conn2);
	ck_assert_int_eq(ret, 0);
	gettimeofday(&tv2, NULL);
	printf ("Total time = %f seconds\n", (double) (tv2.tv_usec - tv1.tv_usec) / 1000000 + (double) (tv2.tv_sec - tv1.tv_sec));

	gettimeofday(&tv1, NULL);
	ret = ncot_connection_send(context, conn2, message, strlen(message), NCOT_PACKET_COMMAND);
	ck_assert_int_eq(ret, strlen(message));
	gettimeofday(&tv2, NULL);
	printf ("Total time = %f seconds\n", (double) (tv2.tv_usec - tv1.tv_usec) / 1000000 + (double) (tv2.tv_sec - tv1.tv_sec));

	gettimeofday(&tv1, NULL);
	FD_ZERO(&rfds); FD_ZERO(&wfds);
	highestfd = ncot_set_fds(context, &rfds, &wfds);
	r = pselect(highestfd + 1, &rfds, &wfds, NULL, NULL, NULL);
	if (r > 0) {
		NCOT_DEBUG("log: input/ouput ready\n");
		ncot_process_fd(context, r, &rfds, &wfds);
	}
	ck_assert(r > 0);
	gettimeofday(&tv2, NULL);
	printf ("Total time = %f seconds\n", (double) (tv2.tv_usec - tv1.tv_usec) / 1000000 + (double) (tv2.tv_sec - tv1.tv_sec));

	FD_ZERO(&rfds); FD_ZERO(&wfds);
	highestfd = ncot_set_fds(context, &rfds, &wfds);
	r = pselect(highestfd + 1, &rfds, &wfds, NULL, NULL, NULL);
	if (r > 0) {
		NCOT_DEBUG("log: input/ouput ready\n");
		ncot_process_fd(context, r, &rfds, &wfds);
	}
	ck_assert(r > 0);

#define INCOMPLETE_MESSAGE_LENGTH 16
	/* Send an incomplete message to simulate high i/o load */
	messagepointer = malloc(strlen(messageraw) + 1);
	strncpy(messagepointer, messageraw, strlen(messageraw));
	uint16_t *pint;
	pint = (uint16_t*)&messagepointer[16];
	NCOT_DEBUG("pint          : 0x%x\n", pint);
	NCOT_DEBUG("messagepointer: 0x%x\n", messagepointer);
	*pint = htons(strlen(messageraw) - NCOT_PACKET_DATA_HEADER_LENGTH);
	NCOT_DEBUG("length converted.\n");
	ret = ncot_connection_send_raw(context, conn2, messageraw, INCOMPLETE_MESSAGE_LENGTH);
	ck_assert_int_eq(ret, INCOMPLETE_MESSAGE_LENGTH);

	FD_ZERO(&rfds);	FD_ZERO(&wfds);
	highestfd = ncot_set_fds(context, &rfds, &wfds);
	r = pselect(highestfd + 1, &rfds, &wfds, NULL, NULL, NULL);
	if (r > 0) {
		NCOT_DEBUG("log: input/ouput ready\n");
		ncot_process_fd(context, r, &rfds, &wfds);
	}
	ck_assert(r > 0);

	FD_ZERO(&rfds);	FD_ZERO(&wfds);
	highestfd = ncot_set_fds(context, &rfds, &wfds);
	r = pselect(highestfd + 1, &rfds, &wfds, NULL, NULL, NULL);
	if (r > 0) {
		NCOT_DEBUG("log: input/ouput ready\n");
		ncot_process_fd(context, r, &rfds, &wfds);
	}
	ck_assert(r > 0);

	/* Send another two bytes to have the header complete */
	ret = ncot_connection_send_raw(context, conn2, messagepointer + INCOMPLETE_MESSAGE_LENGTH, 2);
	ck_assert_int_eq(ret, 2);

	FD_ZERO(&rfds);	FD_ZERO(&wfds);
	highestfd = ncot_set_fds(context, &rfds, &wfds);
	r = pselect(highestfd + 1, &rfds, &wfds, NULL, NULL, NULL);
	if (r > 0) {
		NCOT_DEBUG("log: input/ouput ready\n");
		ncot_process_fd(context, r, &rfds, &wfds);
	}
	ck_assert(r > 0);

	FD_ZERO(&rfds);	FD_ZERO(&wfds);
	highestfd = ncot_set_fds(context, &rfds, &wfds);
	r = pselect(highestfd + 1, &rfds, &wfds, NULL, NULL, NULL);
	if (r > 0) {
		NCOT_DEBUG("log: input/ouput ready\n");
		ncot_process_fd(context, r, &rfds, &wfds);
	}
	ck_assert(r > 0);

	/* Send rest of message */
	ret = ncot_connection_send_raw(context, conn2, messagepointer + INCOMPLETE_MESSAGE_LENGTH + 2, 10);
	ck_assert_int_eq(ret, 10);

	FD_ZERO(&rfds);	FD_ZERO(&wfds);
	highestfd = ncot_set_fds(context, &rfds, &wfds);
	r = pselect(highestfd + 1, &rfds, &wfds, NULL, NULL, NULL);
	if (r > 0) {
		NCOT_DEBUG("log: input/ouput ready\n");
		ncot_process_fd(context, r, &rfds, &wfds);
	}
	ck_assert(r > 0);

	FD_ZERO(&rfds);	FD_ZERO(&wfds);
	highestfd = ncot_set_fds(context, &rfds, &wfds);
	r = pselect(highestfd + 1, &rfds, &wfds, NULL, NULL, NULL);
	if (r > 0) {
		NCOT_DEBUG("log: input/ouput ready\n");
		ncot_process_fd(context, r, &rfds, &wfds);
	}
	ck_assert(r > 0);

	free(messagepointer);
	ck_assert(conn1 == NULL);
	ncot_context_free(&context);
	ncot_done();
	/* We need to sleep here for a while to see in the log files
	 * wether the pselect loops run away, until we find a way to
	 * check against that with a ck_assert statement */
	sleep(2);
	/* When the following fails, our daemon process probably
	 * segfaulted! */
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
	tcase_set_timeout(tc_core, 30);
	/* The simple test is disabled because ncot_connection_connect
	 * now blocks because of the GnuTLS handshake. */
	/*tcase_add_test(tc_core, test_connection_simple);*/
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
