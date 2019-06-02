#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef _WIN32
#include <winsock2.h>
#elif __unix__
#include <sys/select.h>
#endif
#include <sys/time.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "autoconfig.h"
#include "ncot.h"
#include "init.h"
#include "select.h"
#include "context.h"
#define DEBUG 1
#include "debug.h"
#include "log.h"

struct ncot_context *context;

int count = 0;
int last_signum = 0;
int r;
int gpid;

void
sig_handler(int signum) {
	count++;
	last_signum = signum;
}

struct sigaction new_action;
struct sigaction old_action;

int
main(int argc, char **argv)
{
	int r, highestfd;
	fd_set rfds, wfds;

	new_action.sa_handler = sig_handler;
	sigemptyset (&new_action.sa_mask);
	new_action.sa_flags = 0;
	sigaction (SIGINT, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN)
		sigaction (SIGINT, &new_action, NULL);
	sigaction (SIGHUP, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN)
		sigaction (SIGHUP, &new_action, NULL);
	sigaction (SIGTERM, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN)
		sigaction (SIGTERM, &new_action, NULL);

	context = ncot_context_new();
	ncot_context_init(context);
	ncot_arg_parse(context->arguments, argc, argv);
	ncot_init();
	ncot_log_set_logfile(context->arguments->logfile_name);
	NCOT_LOG_INFO("%s %s\n", PACKAGE_STRING, "client");
	NCOT_LOG_INFO("%s our PID is %ld\n", PACKAGE_STRING, (long) getpid());

	/* initialize main loop */
	NCOT_LOG(NCOT_LOG_LEVEL_INFO, "entering main loop, CTRL-C to bail out\n");

		int loop_counter = 0;
	do {
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);

		/* need to get highest FD number to pass to pselect next */
		/* we need to fill our fdsets with the sd of our connections */
		highestfd = ncot_set_fds(context, &rfds, &wfds);

		r = pselect(highestfd + 1, &rfds, &wfds, NULL, NULL, NULL);

		if (r > 0) {
			NCOT_LOG(NCOT_LOG_LEVEL_INFO, "log: input/ouput ready\n");
			NCOT_DEBUG("input/ouput ready\n");
			ncot_process_fd(context, r, &rfds, &wfds);
		} else {
			switch (errno) {
			case EBADF:
				NCOT_LOG(NCOT_LOG_LEVEL_ERROR, "error during pselect: EBADF\n");
				break;
			case EINTR:
				NCOT_LOG(NCOT_LOG_LEVEL_INFO, " signal during pselect: EINTR\n");
				break;
			case EINVAL:
				NCOT_LOG(NCOT_LOG_LEVEL_ERROR, "error during pselect: EINVAL\n");
				break;
			case ENOMEM:
				NCOT_LOG(NCOT_LOG_LEVEL_ERROR, "error during pselect: ENOMEM\n");
				break;
			default:
				NCOT_LOG(NCOT_LOG_LEVEL_ERROR, "error during pselect: unknown (should never happen)\n");
			}
		}
		if (last_signum != 0) {
			break;
		}
		/*sleep(1);*/
		loop_counter++;
		/* Before we have a clean running loop we keep this
		 * restriction to simplify testing */
	} while (loop_counter < 128);

	NCOT_LOG(NCOT_LOG_LEVEL_INFO, "%d signals handled\n", count);
	ncot_context_free(&context);

	NCOT_LOG(NCOT_LOG_LEVEL_INFO, "done\n");
	ncot_done();

	return 0;
}

