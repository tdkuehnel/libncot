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
	int i, fd, pid;
	struct stat pidfilestat;
	char pidbuf[7] = {0};
	/* Remove stale pid files from failed tests */
	/*system("unlink ncotd1.pid");*/
	i = stat(PIDFILE_NAME_1, &pidfilestat);
	if (i == 0) unlink(PIDFILE_NAME_1);

	printf("test_ncot PID is %ld\n", (long) getpid());

	i = system("../src/ncotd -d --pidfile=ncotd1.pid --logfile=test_ncot.log");
	ck_assert(i == 0);
	sleep(1);
	i = stat(PIDFILE_NAME_1, &pidfilestat);
	ck_assert(i == 0);

	fd = open(PIDFILE_NAME_1, O_RDONLY);
	ck_assert(fd > 0);

	read(fd, &pidbuf, 6);
	pid = strtol((const char*)&pidbuf, NULL, 10);

	close(fd);

	i = system("cat ncotd1.pid | xargs kill");
	ck_assert(i == 0);

	sleep(1);

	i = stat(PIDFILE_NAME_1, &pidfilestat);
	ck_assert(i != 0);

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
	srunner_set_fork_status (sr, CK_FORK);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
