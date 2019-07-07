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

#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))

void setup()
{
}

void teardown()
{
}

/* Every test gets its own set of port numbers to avoid side
 * effects */

#define TEST_CONNECTION_SIMPLE_CLIENT_PORT  24003
#define TEST_CONNECTION_SIMPLE_SERVER_PORT  "24003"
#define TESTADDRESS_STRING "127.0.0.1"
#define TEST_PACKET_DATA "NCOT 0.0.1 This is raw packet data."

START_TEST (test_packet)
{
	struct ncot_connection *conn1;
	struct ncot_connection *conn2;
	struct ncot_context *context;
	struct ncot_packet *packet;
	struct ncot_packet *npacket;
	int ret;

	ncot_init();
	context = ncot_context_new();
	ncot_log_set_logfile("test_packet.log");

	packet = ncot_packet_new();
	ck_assert(packet != NULL);

	ret = ncot_packet_set_data(packet, TEST_PACKET_DATA, strlen(TEST_PACKET_DATA));
	ck_assert(ret == strlen(TEST_PACKET_DATA));

	ncot_packet_set_subtype(packet, NCOT_PACKET_IDENTIFIER_COMMAND);
	ret = ncot_packet_is_subtype(packet, NCOT_PACKET_IDENTIFIER_COMMAND);
	ck_assert(ret == 0);

	ret = ncot_packet_is_subtype(packet, NCOT_PACKET_IDENTIFIER_RESPONSE);
	ck_assert(ret != 0);

	ncot_packet_free(&packet);
	ck_assert(packet == NULL);

	npacket = NULL;
	ret = ncot_packet_set_data(npacket, TEST_PACKET_DATA, strlen(TEST_PACKET_DATA));
	ck_assert(ret == -1);

	ncot_packet_free(&npacket);

	ncot_context_free(&context);
	ncot_done();
}
END_TEST

Suite * helper_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Packet");

	/* Core test case */
	tc_core = tcase_create("Core");
	tcase_add_unchecked_fixture(tc_core, setup, teardown);
	tcase_set_timeout(tc_core, 12);
	tcase_add_test(tc_core, test_packet);
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
