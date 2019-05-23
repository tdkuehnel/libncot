#include "autoconfig.h"
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "ncot.h"
#include "node.h"

#include "utlist.h"

#include "context.h"

#define DEBUG 1
#include "debug.h"
#include "log.h"

struct ncot_context *context;
struct ncot_node *node;

int count = 0;
int last_signum = 0;
int r;
char *buf;
int gpid;

void sig_handler(int signum) {
	count++;
	last_signum = signum;
}

struct sigaction new_action, old_action;
/* cpwpipe *tpipe, *ipipe, *inpipe, *outpipe; */

void setup_listen_socket()
{
}

int daemonize()
{
	int i, fd, pid;
	pid_t sid;
	struct stat pidfilestat;
	char pidbuf[7] = {0};

	NCOT_LOG_INFO("daemonizing\n");
	/* check if we are still running with this pidfile name, or there is a stale one */
	i = stat(context->arguments->pidfile_name, &pidfilestat);
	if (i == 0) {
		if (pidfilestat.st_size <= 6) {
			fd = open(context->arguments->pidfile_name, O_RDONLY);
			if (fd > 0) {
				read(fd, &pidbuf, 6);
				printf("pid of pidfile %s: %s\n", context->arguments->pidfile_name, &pidbuf);
				close(fd);
				pid = strtol((const char*)&pidbuf, NULL, 10);
				i = kill(pid, 0);
				if (i == 0) {
					printf("process with pid %d found\n", pid);
					return 0;
				} else {
					printf("no process with pid %d, removing stale pidfile\n", pid);
					i = unlink(context->arguments->pidfile_name);
				}
			}
		}
	}

	i = fork();
	if (i < 0) {
		NCOT_LOG_INFO("unable to fork, exiting %d\n");
		ncot_context_free(&context);
		ncot_done();
		exit(EXIT_FAILURE);
	}
	if (i) {
		NCOT_LOG_INFO("parent exiting, pid of child: %d\n", i);
		ncot_context_free(&context);
		ncot_done();
		_exit(EXIT_SUCCESS);
	}
	sid = setsid();
	if (sid < 0) {
		NCOT_LOG_INFO("unable for child to setsid, exiting %d\n");
		ncot_context_free(&context);
		ncot_done();
		exit(EXIT_FAILURE);
	}
	i = fork();
	if (i < 0) {
		NCOT_LOG_INFO("child unable to fork, exiting %d\n");
		ncot_context_free(&context);
		ncot_done();
		exit(EXIT_FAILURE);
	}
	if (i) {
		NCOT_LOG_INFO("child exiting, pid of daemon: %d\n", i);
		fd = creat(context->arguments->pidfile_name, S_IRWXU);
		if (fd > 0) {
			snprintf((char*)&pidbuf, 7, "%d", i);
			write(fd, &pidbuf, strlen((const char*)&pidbuf));
			close(fd);
		}
		ncot_context_free(&context);
		ncot_done();
		exit(EXIT_SUCCESS);
	}
	ncot_log_set_logfile(context->arguments->logfile_name);
	NCOT_LOG_INFO("%s child daemonized\n", PACKAGE_STRING);

}

void ncot_client_init(int argc, char **argv) {
	char *str;
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

	/* command line parsing */
	/* initialize global context */
	context = ncot_context_new();
	ncot_context_init(context);

	ncot_arg_parse(context->arguments, argc, argv);
	ncot_init();
	NCOT_LOG_INFO("%s %s\n", PACKAGE_STRING, "client");
	if (context->arguments->daemonize) daemonize();
	if (context->arguments->daemonize) NCOT_LOG_INFO("%s Looks like we are running as a deamon, good.\n", PACKAGE_STRING);

	NCOT_LOG_INFO("%s our PID is %ld\n", PACKAGE_STRING, (long) getpid());

/*	node = ncot_node_new();
	if (node) {
		ncot_node_init(node);
		str = NULL;
		uuid_export(node->uuid, UUID_FMT_STR, &str, NULL);
		NCOT_LOG_INFO("Node created with uuid: %s \n", str);

	} else {
		NCOT_LOG_WARNING("unable to create ncot node.");
	}
*/
	/* main initialization ends here */
}

int
get_highest_fd(struct ncot_context *context)
{
	int maxfd = 0;
	if (context->controlconnection->status == NCOT_CONN_LISTEN ||
		context->controlconnection->status == NCOT_CONN_CONNECTED) {
		if (context->controlconnection->sd > maxfd)
			maxfd = context->controlconnection->sd;
	}
	/* Here we need to check the remaining available connections
	 * when they are implemented */
	return maxfd;
}

int
main(int argc, char **argv)
{
	int r, highestfd;
	fd_set rfds, wfds;
	sigset_t sigmask;

	ncot_client_init(argc, argv);
	ncot_connection_listen(context->controlconnection, atoi(context->arguments->port));

	/* initialize main loop */
	NCOT_LOG( NCOT_LOG_LEVEL_INFO, "entering main loop, CTRL-C to bail out\n");

	int loop_counter = 0;
	do {
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);

		NCOT_DEBUG("\n");

		/* need to get highest FD number to pass to pselect next */
		highestfd = get_highest_fd(context);
		/* we need to fill our fdsets with the sd of our connections */
		ncot_set_fds(context, &rfds, &wfds);

		r = pselect(highestfd + 1, &rfds, &wfds, NULL, NULL, NULL);

		if (r > 0) {
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
	} while (loop_counter < 12);

	NCOT_LOG(NCOT_LOG_LEVEL_INFO, "%d signals handled\n", count);
	kill(gpid, SIGTERM);

	ncot_node_free(&node);

	if (context->arguments->daemonize) {
		struct stat pidfilestat;
		if (stat(context->arguments->pidfile_name, &pidfilestat) == 0) unlink(context->arguments->pidfile_name);
	}

	ncot_context_free(&context);

	NCOT_LOG(NCOT_LOG_LEVEL_INFO, "done\n");
	ncot_done();

	return 0;

}
