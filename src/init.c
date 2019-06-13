#include "autoconfig.h"

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
	ncot_log_init(NCOT_LOG_LEVEL_WARNING);
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
