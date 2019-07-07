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

/** This is for connecting to a remote ncot daemon via a secure control connection */

void
ncot_shell_handle_connect_3(struct ncot_context *context, char *command)
{
	int ret;
	if (command[0] == '\0') {
		ncot_shell_reset(context->shell);
		free(context->shell->subdata);
		DPRINTF(context->shell->writefd, "command aborted.\n");
		return;
	}
	ret = ncot_connection_connect(context, (struct ncot_connection*)context->shell->data, command, (char*)context->shell->subdata);
	DPRINTF(context->shell->writefd, "connect operation returned %d\n", ret);
	ret = ncot_connection_authenticate_server((struct ncot_connection*)context->shell->data);
	DPRINTF(context->shell->writefd, "remote authentication operation returned %d\n", ret);
	context->shell->isremote = 1;
	ncot_shell_reset(context->shell);
}

void
ncot_shell_handle_connect_2(struct ncot_context *context, char *command)
{
	if (command[0] == '\0') {
		ncot_shell_reset(context->shell);
		DPRINTF(context->shell->writefd, "command aborted.\n");
		return;
	}
	context->shell->subdata = malloc(strlen(command) + 1);
	strncpy(context->shell->subdata, command, strlen(command) + 1);
	ncot_shell_handle_interaction(context->shell, "Enter Port to connect to", ncot_shell_handle_connect_3, NULL);
}

void
ncot_shell_handle_connect(struct ncot_context *context, char *command, char *base)
{
	if (!context->controlconnection) {
		DPRINTF(context->shell->writefd, "No control connection available\n");
		return;
	}
	if (!(context->controlconnection->status != NCOT_CONN_AVAILABLE || context->controlconnection->status != NCOT_CONN_INIT)) {
		DPRINTF(context->shell->writefd, "Control connection in status %s, cannot connect\n", ncot_connection_get_status_string(context->controlconnection));
		return;
	}
	ncot_shell_handle_interaction(context->shell, "Enter Address of remote ncot daemon to connect to", ncot_shell_handle_connect_2, (void*)context->controlconnection);
}
