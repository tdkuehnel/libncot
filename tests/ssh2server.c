#include "../autoconfig.h"

#include <libssh2.h>

#ifdef HAVE_WINDOWS_H
# include <windows.h>
#endif
#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
# ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
# ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>


const char *keyfile1="~/.ssh/id_rsa.pub";
const char *keyfile2="~/.ssh/id_rsa";
const char *username="username";
const char *password="password";

int accept_one_connection(int port);
void error_exit(const char *msg);

#define PORT 32400

int main(int argc, char **argv)
{
	int rc;
	int intsock;
	int i;
	int auth_pw = 0;
	LIBSSH2_SESSION *session;
	const char *fingerprint;
#ifdef WIN32
	WSADATA wsadata;
	int err;

	err = WSAStartup(MAKEWORD(2,0), &wsadata);
	if (err != 0) {
		fprintf(stderr, "WSAStartup failed with error: %d\n", err);
		return 1;
	}
#endif
	rc = libssh2_init (0);
	if (rc != 0) {
		fprintf (stderr, "libssh2 initialization failed (%d)\n", rc);
		return 1;
	}

	// Accept a TCP connection.
	intsock = accept_one_connection(PORT);

	session = libssh2_session_init();
	libssh2_session_set_blocking(session, 0);

	while((rc = libssh2_session_handshake(session, intsock)) == LIBSSH2_ERROR_EAGAIN);
	if(rc) {
		fprintf(stderr, "Failure establishing SSH session: %d\n", rc);
		return -1;
	}

	fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
	fprintf(stderr, "Fingerprint: ");
	for(i = 0; i < 20; i++) {
		fprintf(stderr, "%02X ", (unsigned char)fingerprint[i]);
	}
	fprintf(stderr, "\n");



	libssh2_session_free(session);

#ifdef WIN32
	closesocket(intsock);
#else
	close(intsock);
#endif
	fprintf(stderr, "all done!\n");

	libssh2_exit();

	return 0;
}

// Listens on 'port' for a TCP connection. Accepts at most one connection.
int accept_one_connection(int port)
{
	int res;
	// Listen for a TCP connection.
	struct sockaddr_in serv_addr;
	int listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd < 0) {
		error_exit("socket() failed.\n");
	}
	int yes = 1;
	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		error_exit("setsockopt() failed.\n");
	}
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(port);
	res = bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
	if (res < 0) {
		error_exit("bind() failed.\n");
	}
	res = listen(listenfd, 10);
	if (res < 0) {
		error_exit("listen() failed.\n");
	}

	printf("Waiting for a connection...\n");

	// Accept a TCP connection.
	int connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);
	if (connfd < 0) {
		error_exit("accept() failed.\n");
	}

	printf("A client connected!\n");

	close(listenfd);

	return connfd;
}

void error_exit(const char *msg)
{
	printf("ERROR: %s", msg);
	exit(1);
}
