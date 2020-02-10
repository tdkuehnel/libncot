#include <stdlib.h>
#include <check.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>

/*#include "../src/config.h"
  #include "../src/helper.h"
*/

#include "../src/log.h"

#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))
#define PIDFILE_NAME_TEST_NCOT "test_ncotd.pid"

void setup()
{
}

void teardown()
{
	int i;
	struct stat logfilestat;
	i = stat("logfilename", &logfilestat);
	if (i == 0) {
		unlink("logfilename");
	}

	struct stat pidfilestat;
	sleep(1);
	printf("teardown\n");
	if (stat(PIDFILE_NAME_TEST_NCOT, &pidfilestat) == 0) {
		printf("executing kill by pid\n");
		system("cat " PIDFILE_NAME_TEST_NCOT " | xargs kill");
	}

}

START_TEST (test_logfile)
{
	char *s1 = "";
	char *s2 = "logfilename";
	int ret;

	ncot_log_init(NCOT_LOG_LEVEL_DEFAULT);
	ret = ncot_log_set_logfile(s1);
	ck_assert(ret == -1);
	ret = ncot_log_set_logfile(s2);
	ck_assert(ret == 0);
	ncot_log_done();
}
END_TEST

START_TEST (test_ncot)
{
	int i, fd, pid;
	struct stat pidfilestat;
	char pidbuf[7] = {0};
	/* Remove stale pid files from failed tests */
	/*system("unlink ncotd1.pid");*/
	/* sleep(1); Give the former test ncotd time to clean up */
	i = stat(PIDFILE_NAME_TEST_NCOT, &pidfilestat);
	if (i == 0) unlink(PIDFILE_NAME_TEST_NCOT);

	printf("test_ncot PID is %ld\n", (long) getpid());

#ifdef _WIN32
	i = system("../src/ncot.exe --pidfile=" PIDFILE_NAME_TEST_NCOT " --logfile=test_ncot.log");
#else   
	i = system("../src/ncot -d --pidfile=" PIDFILE_NAME_TEST_NCOT " --logfile=test_ncot.log");
#endif
	ck_assert(i == 0);
	sleep(1);
	i = stat(PIDFILE_NAME_TEST_NCOT, &pidfilestat);
	ck_assert(i == 0);

	fd = open(PIDFILE_NAME_TEST_NCOT, O_RDONLY);
	ck_assert(fd > 0);

	read(fd, &pidbuf, 6);
	pid = strtol((const char*)&pidbuf, NULL, 10);

	close(fd);

	i = system("cat " PIDFILE_NAME_TEST_NCOT " | xargs kill");
	ck_assert(i == 0);

	/*sleep(1);*/

	i = stat(PIDFILE_NAME_TEST_NCOT, &pidfilestat);
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
	tcase_add_test(tc_core, test_logfile);
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
