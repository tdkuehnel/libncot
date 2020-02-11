#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <check.h>


#define ARRAY_LENGTH 4

START_TEST (test_chararray)
{

	char simplearray[ARRAY_LENGTH] = "123\0";
	/* char(* fixedparray)[ARRAY_LENGTH] = {'1','2','3','4'}; */

	ck_assert(simplearray[0] == '1');
	ck_assert(simplearray[1] == '2');
	ck_assert(simplearray[2] == '3');
	ck_assert(simplearray[3] == '\0');
	/* char simplearray[ARRAY_LENGTH] = "1234";          // This is the old and wrong way of doing it!  */
	/* ck_assert(simplearray[4] == '\0');                // This is actually referencing the fifth byte ! */
	/* ck_assert(simplearray[5] == '\0');                // ?? Why don't we get a compiler warning ? */
	/* ck_assert(simplearray[ARRAY_LENGTH] == '\0');     // This too */
	/* simplearray[ARRAY_LENGTH] = '5';                  // Looks we can happily assign to it. */
	/* ck_assert(simplearray[ARRAY_LENGTH] == '5');      // And read it. */
	ck_assert(sizeof(simplearray) == ARRAY_LENGTH);     //But sizeof it is allways ARRAY_LENGTH
	ck_assert(strlen(simplearray) == ARRAY_LENGTH -1);
}
END_TEST

#define STR_MAX_LEN 12

START_TEST (test_strterminate)
{
	/* This is to demonstrate how to use dynamic fixed length char
	 * arrays */
	/* Based on this nice finding:
	 * https://stackoverflow.com/questions/1810083/c-pointers-pointing-to-an-array-of-fixed-size */

	char (*s)[STR_MAX_LEN];                              // s is pinter to fixed length array, uninitialized
	ck_assert(sizeof(*s) == STR_MAX_LEN);                // sizeof gives size of whole array
	s = malloc(sizeof(*s));                              // allows for nice malloc of actual needed size
	strncpy((char*)s, "0123456789abc", STR_MAX_LEN);     // strncpy usage
	ck_assert(strlen((char*)s) > STR_MAX_LEN);           // leads to error prone results
	(*s)[STR_MAX_LEN-1] = '\0';                          // when not proper 0 terminated
	ck_assert(strlen((char*)s) == STR_MAX_LEN -1);       // looks ok
	free(s);
}
END_TEST


Suite * clanguage_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("CLanguage");

	/* Core test case */
	tc_core = tcase_create("Core");
	/* tcase_add_unchecked_fixture(tc_core, setup, teardown); */
	tcase_add_test(tc_core, test_chararray);
	tcase_add_test(tc_core, test_strterminate);
	suite_add_tcase(s, tc_core);
	return s;
}

int main(void)
{
	int number_failed;
	Suite *s;
	SRunner *sr;

	s = clanguage_suite();
	sr = srunner_create(s);
	srunner_set_fork_status (sr, CK_FORK);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
