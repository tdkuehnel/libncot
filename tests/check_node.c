#include <stdlib.h>
#include <check.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include "../src/utlist.h"
#include "../src/node.h"
#include "../src/connection.h"
#include "../src/log.h"
#include "../src/ncot.h"
#include "../src/context.h"

#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))
#define PIDFILE_NAME_1 "ncotd1.pid"

void setup()
{
}

void teardown()
{
}

START_TEST (test_find_node_by_connection)
{

	struct ncot_context *context;
	struct ncot_node *node1;
	struct ncot_node *node2;
	struct ncot_node *resultnode;
	struct ncot_connection *conn1;
	struct ncot_connection *conn2;
	struct ncot_connection *conn3;

	ncot_init();
	context = ncot_context_new();
	node1 = ncot_node_new();
	node2 = ncot_node_new();
	LL_APPEND(context->globalnodelist, node1);
	LL_APPEND(context->globalnodelist, node2);
	ncot_node_init(node1);
	ncot_node_init(node2);
	conn1 = ncot_connection_new();
	conn2 = ncot_connection_new();
	conn3 = ncot_connection_new();
	LL_APPEND(node1->connections, conn1);
	LL_APPEND(node2->connections, conn2);

	resultnode = ncot_context_get_node_by_connection(context, conn1);
	ck_assert(resultnode == node1);
	resultnode = ncot_context_get_node_by_connection(context, conn2);
	ck_assert(resultnode == node2);
	resultnode = ncot_context_get_node_by_connection(context, conn3);
	ck_assert(resultnode == NULL);

	ncot_connection_free(&conn1);
	ncot_connection_free(&conn2);
	ncot_node_free(&node1);
	ncot_node_free(&node2);
	ncot_context_free(&context);

	ncot_done();
}
END_TEST

START_TEST (test_node)
{

	struct ncot_node *node;

	node = NULL;

	node = ncot_node_new();
	ck_assert(node != NULL);

	ncot_node_init(node);

	ncot_node_free(&node);
	ck_assert(node == NULL);

}
END_TEST


Suite * helper_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Node");

	/* Core test case */
	tc_core = tcase_create("Core");
	tcase_add_checked_fixture(tc_core, setup, teardown);

	tcase_add_test(tc_core, test_find_node_by_connection);
	tcase_add_test(tc_core, test_node);
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
