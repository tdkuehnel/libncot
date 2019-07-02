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
#include "identity.h"
#include "error.h"
#include "node.h"

void
ncot_shell_handle_context(struct ncot_context *context, char *command, char *base)
{
	struct ncot_shell *shell;
	shell = context->shell;
	ncot_shell_identity_list(context);
	ncot_shell_nodes_list(context);
}
