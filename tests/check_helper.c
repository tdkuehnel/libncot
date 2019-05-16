#include <stdlib.h>
#include <check.h>
/*#include "../src/context.h"

#include "../src/config.h"
#include "../src/helper.h"
*/

#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))

START_TEST (test_helper_nct)
{
  /* unit test code 
  char line1[CPW_CONFIG_MAX_LINE_LENGTH] = "<Tag>";
  char line2[CPW_CONFIG_MAX_LINE_LENGTH] = "</Tag>";
  */

  ck_assert(0== 0);
  ck_assert(1 == 1);
}
END_TEST


Suite * helper_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Helper");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_helper_nct);

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
