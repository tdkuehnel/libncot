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
#include "../src/error.h"
#include "../src/db.h"

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
	context->arguments->ncot_dir = "./.ncot";
	return context;
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
	struct ncot_connection_list *list1;
	struct ncot_connection_list *list2;
	struct ncot_connection_list *list3;
	ncot_init();
	ncot_log_set_logfile("test_find_node_by_connection.log");
	NCOT_LOG_INFO("TEST FIND NODE BY CONNECTIONSTARTS HERE\n");

	context = ncot_context_new();
	node1 = ncot_node_new();
	node2 = ncot_node_new();
	LL_APPEND(context->globalnodelist, node1);
	LL_APPEND(context->globalnodelist, node2);
	ncot_node_init(context, node1);
	ncot_node_init(context, node2);
	conn1 = ncot_connection_new();
	conn2 = ncot_connection_new();
	conn3 = ncot_connection_new();
	list1 = ncot_connection_list_new();
	list1->connection = conn1;
	list2 = ncot_connection_list_new();
	list2->connection = conn2;
	list3 = ncot_connection_list_new();
	list3->connection = conn3;
	LL_APPEND(node1->connections, list1);
	LL_APPEND(node2->connections, list2);

	resultnode = ncot_context_get_node_by_connection(context, conn1);
	ck_assert(resultnode == node1);
	resultnode = ncot_context_get_node_by_connection(context, conn2);
	ck_assert(resultnode == node2);
	resultnode = ncot_context_get_node_by_connection(context, conn3);
	ck_assert(resultnode == NULL);

/*	ncot_connection_free(&conn1);
	ncot_connection_free(&conn2);*/
/*	ncot_node_free(&node1);
	ncot_node_free(&node2);*/
	ncot_context_free(&context);

	ncot_done();
}
END_TEST

#define NCOT_READ_BUFLEN 512

struct json_object*
get_json_obj_nodes_from_testfile()
{
	int fd;
	char buf[NCOT_READ_BUFLEN];
	struct json_tokener *tokener;
	struct json_object *jsonobj = NULL;
	enum json_tokener_error jerr;
	int r;

	fd = open("./.ncot/nodes.json", O_RDONLY);
	tokener = json_tokener_new();
	do {
		r = read(fd, &buf, NCOT_READ_BUFLEN);
		jsonobj = json_tokener_parse_ex(tokener, buf, r);
	} while ((jerr = json_tokener_get_error(tokener)) == json_tokener_continue && r != 0);
	close(fd);
 	json_tokener_free(tokener);

	return jsonobj;
}

void
setup_context(struct ncot_context *context)
{

}

START_TEST (test_node_keys)
{

	struct ncot_node *node = NULL;
	struct json_object *jsonobj = NULL;
	struct json_object *jsonarray = NULL;
	struct ssh_key_struct *pkey;
	struct ncot_context *context;
	enum ssh_keytypes_e keytype;
	int r;

	ncot_init();
	ncot_log_set_logfile("test_node_keys.log");
	NCOT_LOG_INFO("TEST NODE KEYS STARTS HERE\n");

	context = new_context();

	/* node = ncot_node_new(); */
	jsonobj = get_json_obj_nodes_from_testfile();
	ck_assert(jsonobj != NULL);
	r = json_object_object_get_ex(jsonobj, "nodes", &jsonarray);
	node = ncot_nodes_new_from_json(context, jsonarray);
	ck_assert(node != NULL);
	/* We have some nodes, like read from our state file. But the
	 * keys are stored elsewhere and get loaded or generated on
	 * demand */

	/* Use file implementation functions directly until we have no
	 * other backend (sql)*/
	pkey = ncot_node_get_public_key(node, NCOT_SSH_KEYTYPE_RSA);
	ck_assert(pkey == NULL);
	r = ncot_db_node_load_pkey(context, node, NCOT_SSH_KEYTYPE_RSA);
	ck_assert(pkey == NCOT_OK);
	pkey = ncot_node_get_public_key(node, NCOT_SSH_KEYTYPE_RSA);
	ck_assert(pkey != NULL);
	ck_assert(ssh_key_is_public(pkey));
	ck_assert(!ssh_key_is_private(pkey));

	ncot_ssh_keypair_free(&node->keyset->keypairs[0]);
	pkey = ncot_node_get_public_key(node, NCOT_SSH_KEYTYPE_RSA);
	ck_assert(pkey == NULL);
	ncot_node_load_keys(context, node, NCOT_SSH_KEYTYPE_RSA);
	ck_assert(node->keyset->keypairs[0]->key != NULL);
	ck_assert(node->keyset->keypairs[0]->pkey != NULL);
	ck_assert(ssh_key_is_private(node->keyset->keypairs[0]->key));
	keytype = ssh_key_type(node->keyset->keypairs[0]->pkey);
	NCOT_LOG_INFO("keytype: %s\n", ssh_key_type_to_char(keytype));
	ck_assert(ssh_key_is_public(node->keyset->keypairs[0]->pkey));
	ck_assert(ssh_key_is_private(node->keyset->keypairs[0]->key));

	ncot_node_load_keys(context, node, NCOT_SSH_KEYTYPE_ALL);
	ck_assert(ssh_key_is_public(node->keyset->keypairs[0]->pkey));
	ck_assert(ssh_key_is_private(node->keyset->keypairs[0]->key));
	ck_assert(ssh_key_is_public(node->keyset->keypairs[1]->pkey));
	ck_assert(ssh_key_is_private(node->keyset->keypairs[1]->key));
	ck_assert(ssh_key_is_public(node->keyset->keypairs[2]->pkey));
	ck_assert(ssh_key_is_private(node->keyset->keypairs[2]->key));

	ncot_node_free(&node->next);
	ncot_node_free(&node);

	/* Maybe check some initialization variants here */
	node = ncot_node_new();
	ncot_node_init(context, node);
	ncot_node_free(&node);
	ck_assert(node == NULL);

	ncot_context_free(&context);
	NCOT_LOG_INFO("TEST NODE KEYS ENDS HERE\n");
	ncot_done();
}
END_TEST

START_TEST (test_node)
{

	struct ncot_node *node;

	node = NULL;

	node = ncot_node_new();
	ck_assert(node != NULL);

	/* ncot_node_init(node); */

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
	tcase_add_test(tc_core, test_node_keys);
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
