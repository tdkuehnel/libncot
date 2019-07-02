#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef _WIN32
#include <winsock2.h>
#include <windef.h>
#elif __unix__
#include <sys/select.h>
#include <sys/socket.h>
#endif

#include "utlist.h"
#include "shell.h"
#include "context.h"
#include "error.h"

void
ncot_shell_connection_list(struct ncot_context *context, struct ncot_connection *connection)
{
	char *type;
	char *status;
	switch (connection->type) {
	case NCOT_CONN_CONTROL:
		type = "CONTROL";
		break;
	case NCOT_CONN_NODE:
		type = "NODE";
		break;
	case NCOT_CONN_INCOMING:
		type = "INCOMING";
		break;
	case NCOT_CONN_INITIATE:
		type = "INITIATE";
		break;
	default:
		type = "<unknwon>";
	}
	switch (connection->status) {
	case NCOT_CONN_AVAILABLE:
		status = "AVAILABLE";
		break;
	case NCOT_CONN_CONNECTED:
		status = "CONNECTED";
		break;
	case NCOT_CONN_LISTEN:
		status = "LISTEN";
		break;
	case NCOT_CONN_BOUND:
		status = "BOUND";
		break;
	case NCOT_CONN_INIT:
		status = "INIT";
		break;
	default:
		status = "<unknown>";
	}
	DPRINTF(context->shell->writefd, "connection at 0x%0x: %s %s\n", connection, type, status);
}

void
ncot_shell_handle_connection(struct ncot_context *context, char *command, char *base)
{
	struct ncot_shell *shell;
	shell = context->shell;
	DPRINTF(shell->writefd, "not implemented\n");
}
