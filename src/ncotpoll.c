#include "autoconfig.h"

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <poll.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#include "ncot.h"
#include "init.h"
#include "context.h"
#include "shell.h"
#include "debug.h"
#include "log.h"
#include "error.h"
#include "select.h"
#include "shell.h"

static int error = 0;
static int terminate = 0;
static int signalcount = 0;
static int lastsignum = 0;

#ifdef _WIN32
PHANDLE handle1;
PHANDLE handle2;
#else
int pipefd[2];
struct sigaction new_action;
struct sigaction old_action;
#endif
char sendbyte = '.';

int dummy_event_callback(socket_t fd, int revents, void *userdata)
{
}

void
sig_handler(int signum) {
	int got_sighup = 0;
	int got_sigint = 0;
	switch (signum) {
#ifdef _WIN32
	case SIGTERM:
	case SIGABRT:
	case SIGBREAK:
#else
	case SIGHUP:
#endif
		got_sighup = 1;
		break;
	case SIGINT:
		got_sigint = 1;
		break;
	}
	signalcount++;
	lastsignum = signum;
	terminate = 1;
#ifdef _WIN32
	send(handle1, &sendbyte, 1, 0);
#else
	write(pipefd[1], &sendbyte, 1);
#endif
}

/* extern struct ssh_event_struct *mainloop; */

int
main(int argc, char **argv)
{
	struct ncot_context *context;
	struct ncot_arguments *arguments;

	int r;

#ifdef _WIN32
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGABRT, sig_handler);
	/* win32_socket_setup(); */
#else
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
#endif
	ncot_init();
	context = ncot_context_new();
	arguments = calloc(1, sizeof(struct ncot_arguments));
	if (ncot_arg_parse(arguments, argc, argv)) {
		ncot_context_free(&context);
		return 1;
	}
	context->arguments = arguments;
	if (context->arguments->logfile_name[0] != '\0') {
		/* context->arguments->logfile_name = "ncotpoll.log"; */
		ncot_log_set_logfile(context->arguments->logfile_name);
	}
	ncot_log_set_loglevel(context->arguments->log_level);
#ifdef _WIN32
	NCOT_LOG_INFO("%s %s\n", PACKAGE_STRING, "client");
#else
	NCOT_LOG_INFO("%s %s\n", PACKAGE_STRING, "client/daemon");
	if (context->arguments->daemonize) ncot_daemonize(context);
	if (context->arguments->daemonize) NCOT_LOG_INFO("%s Looks like we are running as a deamon, good.\n", PACKAGE_STRING);
#endif
	NCOT_LOG_INFO("%s our PID is %ld\n", PACKAGE_STRING, (long) getpid());
	if (ncot_context_init_from_file(context, arguments->config_file) != NCOT_SUCCESS)
		ncot_context_init(context);
	/* mainloop = context->mainloop; */
#ifndef _WIN32
	if (context->arguments->daemonize)
		ncot_connection_listen(context, context->controlconnection,
				atoi(context->arguments->port));
#endif
	if (context->arguments->interactive) {
		/* Dangerous: we rely on context->shell. Solved, we
		 * initialize on this first use if appropriate. */
		context->shell = ncot_shell_new();
		ncot_shell_init(context->shell);
		ncot_shell_print_prompt(context->shell);
	} else {
		/* initialize main loop */
		NCOT_LOG(NCOT_LOG_LEVEL_INFO, "entering main loop, CTRL-C to bail out\n");
	}

#ifdef _WIN32
	r = CreatePipe(handle1, handle2, NULL, 0);
#else
	r = pipe(pipefd);
#endif
	if (r != 0) {
		NCOT_LOG_ERROR("can't create self pipe\n");
		goto out;;
	}
	r = ssh_event_add_fd(context->mainloop, pipefd[0], POLLIN, dummy_event_callback, NULL);
	if (r != SSH_OK) {
		NCOT_LOG_ERROR("error adding dummyfd to event\n");
		goto out;
	}
	ncot_poll_init(context, context->mainloop);

	while (!(terminate) && !(context->terminate)) {
		NCOT_LOG_INFO("Main loop iteration\n");
		ncot_poll_prepare(context, context->mainloop);
		if(error) {
			NCOT_LOG_ERROR("Breaking due to error ssh_event_dopoll\n");
			break;
		}
		r = ssh_event_dopoll(context->mainloop, -1);
		if (r == SSH_ERROR){
			NCOT_LOG_ERROR("Error ssh_event_dopoll\n");
			/* ssh_disconnect(session); */
			/* break;; */
		}
	}
	NCOT_LOG(NCOT_LOG_LEVEL_INFO, "%d signals handled\n", signalcount);
	if (context->arguments->interactive) {
		if (context->shell) DPRINTF(context->shell->writefd, "\n");
	}
	if (context->arguments->daemonize) {
		struct stat pidfilestat;
		if (stat(context->arguments->pidfile_name, &pidfilestat) == 0) unlink(context->arguments->pidfile_name);
	}
out:
	if (pipefd[0] > 0) close(pipefd[0]);
	if (pipefd[1] > 0) close(pipefd[1]);
	ncot_context_free(&context);
	NCOT_LOG(NCOT_LOG_LEVEL_INFO, "%s done\n", PACKAGE_STRING);
	ncot_done();

	return 0;
}
