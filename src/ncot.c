#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef _WIN32
#include <winsock2.h>
#include <windef.h>
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
#include "shell.h"
#define DEBUG 1
#include "debug.h"
#include "log.h"
#include "error.h"

struct ncot_context *context;

int count = 0;
int last_signum = 0;
int r;
int gpid;

#ifdef _WIN32
int fd1;
int fd2;
char sendbyte = '.';
#else
struct sigaction new_action;
struct sigaction old_action;
#endif

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
	count++;
	last_signum = signum;
#ifdef _WIN32
	send(fd1, &sendbyte, 1, 0);
#endif
}

#ifdef _WIN32
int
win32_socket_setup()
{
	WORD wVersionRequested;
	WSADATA wsadata;
	wVersionRequested = MAKEWORD(2, 2);
	r = WSAStartup(wVersionRequested, &wsadata);

	struct sockaddr_in inaddr;
	struct sockaddr addr;
	int lst;
	int ret;
	lst = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (lst == INVALID_SOCKET) {
		NCOT_LOG_ERROR("ncot_socket_pair: socket() -%i\n", WSAGetLastError());
		return -1;
	}
	memset(&inaddr, 0, sizeof(inaddr));
	memset(&addr, 0, sizeof(addr));
	inaddr.sin_family = AF_INET;
	inaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	inaddr.sin_port = 0;
	int yes = 1;
	ret = setsockopt(lst, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));
	SOCKET_ERROR_FAIL(ret, "ncot_socket_pair: setsockopt() %i\n");
	ret = bind(lst, (struct sockaddr *)&inaddr, sizeof(inaddr));
	SOCKET_ERROR_FAIL(ret, "ncot_socket_pair: bind() %i\n");
	ret = listen(lst, 1);
	SOCKET_ERROR_FAIL(ret, "ncot_socket_pair: listen() %i\n");
	int len = sizeof(inaddr);
	getsockname(lst, &addr, &len);
	fd1=socket(AF_INET, SOCK_STREAM, 0);
	INVALID_SOCKET_ERROR(fd1, "ncot_socket_pair: socket() %i\n");
	ret = connect(fd1, &addr, len);
	SOCKET_ERROR_FAIL(ret, "ncot_socket_pair: connect() %i\n");
	fd2 = accept(lst, 0, 0);
	SOCKET_ERROR_FAIL(fd2, "ncot_socket_pair: accept() %i\n");
	closesocket(lst);
}
#endif

int
main(int argc, char **argv)
{
	int r, highestfd;
	fd_set rfds, wfds;
	struct ncot_arguments *arguments;

#ifdef _WIN32
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGABRT, sig_handler);
	win32_socket_setup();
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
	context = ncot_context_new();
	arguments = calloc(1, sizeof(struct ncot_arguments));
	if (ncot_arg_parse(arguments, argc, argv)) {
		ncot_context_free(&context);
		return 1;
	}
	context->arguments = arguments;
	ncot_init();
	ncot_log_set_logfile(context->arguments->logfile_name);
#ifdef _WIN32
	NCOT_LOG_INFO("%s %s\n", PACKAGE_STRING, "client");
#else
	NCOT_LOG_INFO("%s %s\n", PACKAGE_STRING, "client/daemon");
	if (context->arguments->daemonize) ncot_daemonize(context);
	if (context->arguments->daemonize) NCOT_LOG_INFO("%s Looks like we are running as a deamon, good.\n", PACKAGE_STRING);
	if (context->arguments->daemonize)
		ncot_connection_listen(context, context->controlconnection,
				atoi(context->arguments->port));
#endif
	NCOT_LOG_INFO("%s our PID is %ld\n", PACKAGE_STRING, (long) getpid());
	if (ncot_context_init_from_file(context, arguments->config_file) != NCOT_SUCCESS)
		ncot_context_init(context);
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
	int loop_counter = 0;
	do {
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);

#ifdef _WIN32
		ncot_set_fds(context, &rfds, &wfds);
		FD_SET(fd2, &rfds);
		r = select(0, &rfds, &wfds, NULL, NULL);
#else
		/* need to get highest FD number to pass to pselect next */
		/* we need to fill our fdsets with the sd of our connections */
		highestfd = ncot_set_fds(context, &rfds, &wfds);
		r = pselect(highestfd + 1, &rfds, &wfds, NULL, NULL, NULL);
#endif

		if (r > 0) {
			if (context->arguments->interactive) {
			} else {
				NCOT_LOG(NCOT_LOG_LEVEL_INFO, "log: input/ouput ready\n");
				NCOT_DEBUG("input/ouput ready\n");
			}
			if (ncot_process_fd(context, r, &rfds, &wfds) != 0) break;
		} else {
#ifdef _WIN32
			if (r != SOCKET_ERROR)
				NCOT_LOG(NCOT_LOG_LEVEL_ERROR, "error during select: UNKNOWN (should never happen)\n");
			int i;
			i = WSAGetLastError();
			switch (i) {
			case WSANOTINITIALISED:
				NCOT_LOG(NCOT_LOG_LEVEL_ERROR, "error during select: WSANOTINITIALISED\n");
				last_signum = 1;
				break;
			case WSAENETDOWN:
				NCOT_LOG(NCOT_LOG_LEVEL_ERROR, "error during select: WSAENETDOWN\n");
				break;
			case WSAEINVAL:
				NCOT_LOG(NCOT_LOG_LEVEL_ERROR, "error during select: WSAEINVAL\n");
				break;
			case WSAEINTR:
				NCOT_LOG(NCOT_LOG_LEVEL_ERROR, "error during select: WSAEINTR\n");
				break;
			case WSAEINPROGRESS:
				NCOT_LOG(NCOT_LOG_LEVEL_ERROR, "error during select: WSAEINPROGRESS\n");
				break;
			case WSAENOTSOCK:
				NCOT_LOG(NCOT_LOG_LEVEL_ERROR, "error during select: WSAENOTSOCK\n");
				last_signum = 1;
				break;
			case WSAEFAULT:
				NCOT_LOG(NCOT_LOG_LEVEL_ERROR, "error during select: WSAEFAULT\n");
				break;
			default:
				NCOT_LOG(NCOT_LOG_LEVEL_ERROR, "error during select: unknown (should never happen)\n");
			}
#else
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
#endif
		}
		if (last_signum != 0) {
			NCOT_LOG(NCOT_LOG_LEVEL_INFO, "Breaking loop due to signal\n");
			break;
		}
		/*sleep(1);*/
		loop_counter++;
		/* Before we have a clean running loop we keep this
		 * restriction to simplify testing */
	} while (loop_counter < 32);

#ifdef _WIN32
	closesocket(fd1);
	closesocket(fd2);
	WSACleanup();
#endif
	NCOT_LOG(NCOT_LOG_LEVEL_INFO, "%d signals handled\n", count);
	if (context->arguments->daemonize) {
		struct stat pidfilestat;
		if (stat(context->arguments->pidfile_name, &pidfilestat) == 0) unlink(context->arguments->pidfile_name);
	}

	if (context->arguments->interactive) {
		char *s = "shell->buffer";
		ncot_log_hex(s, &context->shell->buffer, (int)(context->shell->pbuffer - context->shell->buffer));
	}

	ncot_context_free(&context);
	NCOT_LOG(NCOT_LOG_LEVEL_INFO, "done\n");
	ncot_done();

	return 0;
}
