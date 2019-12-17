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

int make_one_connection(const char *address, int port);
void error_exit(const char *msg);

#define SERVER_PORT 32400
#define SERVER_IP "127.0.0.1"

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

	// Make a TCP connection to the server.
	intsock = make_one_connection(SERVER_IP, SERVER_PORT);

	session = libssh2_session_init();
	if (libssh2_session_handshake(session, intsock)) {
		fprintf(stderr, "Failure establishing SSH session\n");
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

// Makes a TCP connection to the given IPv4 address and port number.
int make_one_connection(const char *address, int port)
{
	int res;
	int connfd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in serv_addr;
	if (connfd < 0) {
		error_exit("socket() failed.\n");
	}
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	res = inet_pton(AF_INET, address, &serv_addr.sin_addr);
	if (res != 1) {
		error_exit("inet_pton() failed.\n");
	}
	res = connect(connfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
	if (res < 0) {
		error_exit("connect() failed.\n");
	}
	printf("connected to remote\n");
	return connfd;
}

void error_exit(const char *msg)
{
	printf("ERROR: %s", msg);
	exit(1);
}
