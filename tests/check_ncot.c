#include <stdlib.h>
#include <check.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/*#include "../src/config.h"
#include "../src/helper.h"
*/

#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))
#define PIDFILE_NAME_1 "ncotd1.pid"

void setup()
{
}

void teardown()
{
}

START_TEST (test_ncot)
{
  int i;
  struct stat pidfilestat;
  /* Remove stale pid files from failed tests */
  /*system("unlink ncotd1.pid");*/

  i = system("../src/ncotd -d --pidfile=ncotd1.pid");
  ck_assert(i == 0);
  sleep(1);
  i = stat(PIDFILE_NAME_1, &pidfilestat);
  ck_assert(i == 0);
  i = system("cat ncotd1.pid | xargs kill");
  ck_assert(i == 0);
  sleep(1);
  i = stat(PIDFILE_NAME_1, &pidfilestat);
  ck_assert(i == 0);
  

}
END_TEST


Suite * helper_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Ncot");

    /* Core test case */
    tc_core = tcase_create("Core");
    tcase_add_checked_fixture(tc_core, setup, teardown);

    tcase_add_test(tc_core, test_ncot);
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
  
  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
