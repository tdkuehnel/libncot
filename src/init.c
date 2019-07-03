#include "autoconfig.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/gnutls.h>

#include "log.h"
#include "init.h"
#include "context.h"

#ifdef _WIN32

/* This function is no more used as it is implemented in ncot.c
 * directly */
int
ncot_socket_pair(int *fd1, int *fd2)
{
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
    int yes=1;
    ret = setsockopt(lst,SOL_SOCKET,SO_REUSEADDR,(char*)&yes,sizeof(yes));
    if (ret == SOCKET_ERROR) {
	    NCOT_LOG_ERROR("ncot_socket_pair: setsockopt() %i\n", WSAGetLastError());
	    return -1;
    }
    ret = bind(lst,(struct sockaddr *)&inaddr,sizeof(inaddr));
    if (ret == SOCKET_ERROR) {
	    NCOT_LOG_ERROR("ncot_socket_pair: bind() %i\n", WSAGetLastError());
	    return -1;
    }
    ret = listen(lst,1);
    if (ret == SOCKET_ERROR) {
	    NCOT_LOG_ERROR("ncot_socket_pair: listen() %i\n", WSAGetLastError());
	    return -1;
    }
    int len=sizeof(inaddr);
    getsockname(lst, &addr,&len);
    *fd1=socket(AF_INET, SOCK_STREAM,0);
    if (*fd1 == INVALID_SOCKET) {
	    NCOT_LOG_ERROR("ncot_socket_pair: socket() -%i\n", WSAGetLastError());
	    return -1;
    }
    connect(*fd1,&addr,len);
    *fd2=accept(lst,0,0);
    if (*fd2 == INVALID_SOCKET) {
	    NCOT_LOG_ERROR("ncot_socket_pair: accept() -%i\n", WSAGetLastError());
	    return -1;
    }
    closesocket(lst);
    return 0;
}
#endif

void
ncot_init()
{
	ncot_log_init(NCOT_LOG_LEVEL_DEFAULT);

	/* During tests we like to log to different files which is set
	 * up later by ncot_log_set_logfile. This startup message
	 * pollutes the main test log file. Alternatively we could
	 * find a way to provide distinctive instance information to
	 * show up to make the message useful.*/
	/*NCOT_LOG_INFO("%s\n", PACKAGE_STRING);*/
	gnutls_global_init();
	gnutls_global_set_log_level(GNUTLS_LOG_LEVEL);
	gnutls_global_set_log_function(print_logs);

}

void
ncot_done()
{
	gnutls_global_deinit();
	ncot_log_done();
}

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

// GnuTLS will call this function whenever there is a new debugging log message.
void
print_logs(int level, const char* msg)
{
 	NCOT_LOG_INFO("GnuTLS [%d]: %s", level, msg);
}

#ifndef _WIN32
int
ncot_daemonize(struct ncot_context *context)
{
	int i, fd, pid;
	pid_t sid;
	struct stat pidfilestat;
	char pidbuf[7] = {0};

	NCOT_LOG_INFO("%s %s\n", PACKAGE_STRING, "daemonizing");
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
/*	NCOT_LOG_INFO("%s %s\n", PACKAGE_STRING, "before buffer");
	NCOT_LOG_INFO_BUFFERED("now forking ..\n");
	NCOT_LOG_INFO("%s %s\n", PACKAGE_STRING, "before buffer flush");
	NCOT_LOG_INFO_BUFFER_FLUSH();*/
	i = fork();
	if (i < 0) {
		NCOT_LOG_INFO("unable to fork, exiting %d\n");
		ncot_context_free(&context);
		ncot_done();
		exit(EXIT_FAILURE);
	}
	if (i) {
		sleep(1); /* needed for proper log output */
		NCOT_LOG_INFO_BUFFERED("parent exiting, pid of child: %d\n", i);
		NCOT_LOG_INFO_BUFFER_FLUSH();
		ncot_log_done();
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
		sleep(1); /* needed for proper log output */
		NCOT_LOG_INFO_BUFFERED("child exiting, pid of daemon: %d\n", i);
		ncot_log_done();
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
	NCOT_LOG_INFO("%s child daemonized\n", PACKAGE_STRING);

}
#endif
