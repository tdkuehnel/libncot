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
#include "../src/policy.h"

#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))

void setup()
{
}

void teardown()
{
}

#define NCOT_READ_BUFLEN 128

START_TEST (test_policy)
{
	struct ncot_context *context;
	struct ncot_policy *policy;
	struct json_object *jsonobj;
	struct json_object *jsonparse = NULL;
	struct json_object *jsonarray;
	struct json_tokener *tokener;
	enum json_tokener_error jerr;
	int ret;
	int fd;
	int r;
	char buf[NCOT_READ_BUFLEN];
	int numpolicies;
	
	ncot_init();
	context = ncot_context_new();
	ncot_log_set_logfile("test_policy.log");

	policy = ncot_policy_new();
	ck_assert(policy != NULL);

	ncot_policy_set_brief(policy, "Only user with real names");
	ncot_policy_set_category(policy, "Authenticity");
	ncot_policy_set_text(policy, "This policy is intended for use only if you want to make sure the user interact under their real names and identity.");

	fd = open("test_policy.json", O_CREAT|O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	jsonobj = json_object_new_object();
	jsonarray = json_object_new_array();
	ncot_policy_save_to_json(policy, jsonarray);
	json_object_object_add_ex(jsonobj, "policy", jsonarray, JSON_C_OBJECT_KEY_IS_CONSTANT);
	ret = json_object_to_fd(fd, jsonobj, JSON_C_TO_STRING_PRETTY);
	close(fd);
	ncot_policy_free(&policy);

	fd = open("test_policy.json", O_RDONLY);
	tokener = json_tokener_new();
	do {
		r = read(fd, &buf, NCOT_READ_BUFLEN);
		jsonparse = json_tokener_parse_ex(tokener, buf, r);
	} while ((jerr = json_tokener_get_error(tokener)) == json_tokener_continue);

	ret = json_object_object_get_ex(jsonparse, "policy", &jsonarray);
	ck_assert(ret != 0);

	numpolicies = json_object_array_length(jsonarray);
	ck_assert(numpolicies == 1);

	policy = ncot_policies_new_from_json(jsonarray);
	ck_assert(policy != NULL);

	ck_assert_str_eq(policy->brief, "Only user with real names");
	ck_assert_str_eq(policy->category, "Authenticity");
	ck_assert_str_eq(policy->text, "This policy is intended for use only if you want to make sure the user interact under their real names and identity.");
	
	json_tokener_free(tokener);
	close(fd);

	ncot_policy_free(&policy);
	ck_assert(policy == NULL);

	ncot_context_free(&context);
	ncot_done();
}
END_TEST

Suite * helper_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Policy");

	/* Core test case */
	tc_core = tcase_create("Core");
	tcase_add_unchecked_fixture(tc_core, setup, teardown);
	tcase_add_test(tc_core, test_policy);
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
