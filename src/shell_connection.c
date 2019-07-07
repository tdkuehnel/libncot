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
	type = ncot_connection_get_type_string(connection);
	status = ncot_connection_get_status_string(connection);
	DPRINTF(context->shell->writefd, "connection at 0x%0x: type: %s status: %s\n", connection, type, status);
}

void
ncot_shell_handle_connection(struct ncot_context *context, char *command, char *base)
{
	struct ncot_shell *shell;
	shell = context->shell;
	DPRINTF(shell->writefd, "not implemented\n");
}
