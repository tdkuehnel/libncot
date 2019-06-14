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
#include "../src/init.h"
#include "../src/select.h"

#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))
#define PIDFILE_NAME_1 "ncotd1.pid"

void setup()
{
}

void teardown()
{
}

#define WRITESTRING "NCOT"
#define LF "\n"

START_TEST (test_shell)
{
	struct ncot_shell *shell;
	int pipefd[2];
	int res;
	res = pipe(pipefd);
	ck_assert(res == 0);
	shell = ncot_shell_new();
	ncot_shell_init(shell);
	ck_assert(shell != NULL);
	shell->readfd = pipefd[0];
	/*shell->writefd = pipefd[1];*/

	res = write(pipefd[1], WRITESTRING, strlen(WRITESTRING));
	ck_assert(res == strlen(WRITESTRING));
	res = ncot_shell_read_input(shell);
	ck_assert(res == strlen(WRITESTRING));
	ck_assert(shell->pbuffer == shell->buffer + 4);

	res = write(pipefd[1], WRITESTRING, strlen(WRITESTRING));
	ck_assert(res == strlen(WRITESTRING));
	res = ncot_shell_read_input(shell);
	ck_assert(res == strlen(WRITESTRING));
	ck_assert(shell->pbuffer == shell->buffer + 8);

	res = write(pipefd[1], LF, strlen(LF));
	ck_assert(res == strlen(LF));
	res = ncot_shell_read_input(shell);
	ck_assert(res == strlen(LF));
	ck_assert(shell->pbuffer == shell->buffer);


	ncot_shell_free(&shell);
	ck_assert(shell == NULL);
	close(pipefd[0]);
	close(pipefd[1]);
}
END_TEST

Suite * helper_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Shell");

	/* Core test case */
	tc_core = tcase_create("Core");
	tcase_add_checked_fixture(tc_core, setup, teardown);

	tcase_add_test(tc_core, test_shell);
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
