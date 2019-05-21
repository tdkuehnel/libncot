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

#include "../src/node.h"

#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))
#define PIDFILE_NAME_1 "ncotd1.pid"

void setup()
{
}

void teardown()
{
}

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
