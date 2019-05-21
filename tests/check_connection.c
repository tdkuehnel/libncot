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

#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))

void setup()
{
}

void teardown()
{
}

START_TEST (test_connection)
{
  
  struct ncot_connection *conn;

  conn = NULL;
  
  conn = ncot_connection_new();
  ck_assert(conn != NULL);

  ncot_connection_init(conn, NCOT_CONN_CONTROL);

  ncot_connection_free(&conn);

  ck_assert(conn == NULL);

}
END_TEST


Suite * helper_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Connection");

    /* Core test case */
    tc_core = tcase_create("Core");
    tcase_add_checked_fixture(tc_core, setup, teardown);

    tcase_add_test(tc_core, test_connection);
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
