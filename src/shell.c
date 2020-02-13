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
#include "shell_connect.h"

#ifdef _WIN32
char string[2048];
char *stringptr = (char*)string;
int ret;
#endif

void
ncot_shell_reset(struct ncot_shell *shell)
{
	shell->incommand = 0;
	shell->proceed_command = NULL;
	shell->data = NULL;
	shell->interactivetext[0] = '\0';
}

void
ncot_shell_handle_interaction(struct ncot_shell *shell, char *text, void (*proceed_command)(struct ncot_context *context, char *command), void *data)
{
	shell->proceed_command = proceed_command;
	shell->incommand = 1;
	if (data) shell->data = data; /* Only needed to set once on first call during a sequence */
	strncpy(shell->interactivetext, text, NCOT_SHELL_BUFLEN); /* We actually have NCOT_SHELL_BUFLEN + 1 space available */
	shell->interactivetext[NCOT_SHELL_BUFLEN] = '\n';
	return;
}

void
ncot_shell_handle_info(struct ncot_context *context, char *command, char *base)
{
	struct ncot_shell *shell;
	const char *string = NULL;
	char *name = "<no identity>";
	char *node = "<empty>";
	char *cctype = "<none>";
	char *ccstatus = "<none>";
	shell = context->shell;
	if (context->identity)
		name = context->identity->name;
	if (shell->currentnode) {
		uuid_export(shell->currentnode->uuid, UUID_FMT_STR, &string, NULL);
		node = (char*)string;
	}
	if (context->controlconnection) {
		cctype = ncot_connection_get_type_string(context->controlconnection);
		ccstatus = ncot_connection_get_status_string(context->controlconnection);
	}

	DPRINTF(shell->writefd, "Info: name: %s - current node: %s - control connection: %s %s\n", name, node, cctype, ccstatus);
}

void
ncot_shell_print_help(struct ncot_context *context, char *command, char *base)
{
	struct ncot_shell *shell;
	shell = context->shell;
	DPRINTF(shell->writefd, "Commands: identity\n");
	DPRINTF(shell->writefd, "          node\n");
	DPRINTF(shell->writefd, "          connection\n");
	DPRINTF(shell->writefd, "          connect\n");
	DPRINTF(shell->writefd, "          context\n");
	DPRINTF(shell->writefd, "          hexdump\n");
	DPRINTF(shell->writefd, "          quit\n");
	DPRINTF(shell->writefd, "          info\n");
	DPRINTF(shell->writefd, "          help\n");
}

/** push a commandline into the command ringbuffer */
void
ncot_shell_push_command(struct ncot_context *context, char *command)
{
	char *buffer;
	struct ncot_command_line *commandline;
	if (context->shell->commands < NCOT_SHELL_HISTORY_MAX_COMMANDS) {
		commandline = malloc(sizeof(struct ncot_command_line));
		if (!commandline) return;
		commandline->line = calloc(1, sizeof(*commandline->line));
		if (!commandline->line) return;
		strncpy((char*)commandline->line, command, NCOT_COMMAND_LINE_LENGTH);
		(*commandline->line)[NCOT_COMMAND_LINE_LENGTH - 1] = '\0';
		CDL_PREPEND(context->shell->commandlines, commandline);
		context->shell->commands++;
	} else {
		commandline = context->shell->commandlines->prev;
		free(commandline->line);
		commandline->line = calloc(1, sizeof(*commandline->line));
		strncpy((char*)commandline->line, command, NCOT_COMMAND_LINE_LENGTH);
		(*commandline->line)[NCOT_COMMAND_LINE_LENGTH - 1] = '\0';
		context->shell->commandlines = commandline;
	}
}

/** We have a complete command line read in. Let's handle it. Can be
 * interactive requested user input, too. */
/* Function returns non zero when the quit command was encountered (to
 * end the shell), zero otherwise */
int
ncot_shell_handle_command(struct ncot_context *context, char *command)
{
	struct ncot_shell *shell;
	char *token;
	int valid = 0;
	int ret = 0;
	shell = context->shell;
	token = strtok(command, " ");
	if (shell->incommand && shell->proceed_command) {
		shell->proceed_command(context, command);
		return ret;
	}
	/*DPRINTF(shell->writefd, "token: %s\n", token);*/
	if (token) {
		if (!strcmp(token, "identity")) {
			ncot_shell_handle_identity(context, command, token);
			valid = 1;
		}
		if (!strcmp(token, "node")) {
			ncot_shell_handle_node(context, command, token);
			valid = 1;
		}
		if (!strcmp(token, "info")) {
			ncot_shell_handle_info(context, command, token);
			valid = 1;
		}
		if (!strcmp(token, "connection")) {
			ncot_shell_handle_connection(context, command, token);
			valid = 1;
		}
		if (!strcmp(token, "connect")) {
			ncot_shell_handle_connect(context, command, token);
			valid = 1;
		}
		if (!strcmp(token, "context")) {
			ncot_shell_handle_context(context, command, token);
			valid = 1;
		}
		if (!strcmp(token, "help")) {
			ncot_shell_print_help(context, command, token);
			valid = 1;
		}
		if (!strcmp(token, "hexdump")) {
			ncot_shell_handle_hexdump(context, command, token);
			valid = 1;
		}
		if (!strcmp(token, "quit")) {
			valid = 1;
			ret = 1;
		}
		if (!valid)
			DPRINTF(shell->writefd, "unknown command %s\n", command);
	}
	return ret;
}

/** Handle the bytes read into the input buffer. When there is a whole
 * command read (up to and including the newline character), process
 * the command. The new input can be read in parameters asked from the
 * user to type in in interactive commands, too. */
int
ncot_shell_handle_buffer(struct ncot_context *context)
{
	struct ncot_shell *shell;
	char *p;
	char *p0;
	char *command;
	int datarestlen;
	int res;
	shell = context->shell;
	command = malloc(NCOT_MAX_COMMAND_LEN);
	/* Find the first lf */
	p = strchr(shell->buffer, '\n');
	/* Find the end of data in buffer */
	p0 = strchr(shell->buffer, '\0');
	if (p == NULL) {
		NCOT_LOG_INFO("ncot_shell_handle_buffer: partial buffer read\n");
		free(command);
		return 0;
	}
	/* We have found one. Copy string up to lf into command */
	memcpy(command, shell->buffer, p - shell->buffer);
	/* Terminate with null byte */
	command[p - shell->buffer] = '\0';
	/* Clear gap with zeroes */
	memset(shell->buffer, 0, p - shell->buffer + 1);
	/* FIXME: protect against buffer overrun */
	/* Move rest of buffer to beginning of buffer */
	datarestlen = p0 - p - 1;
	memmove(shell->buffer, p + 1, datarestlen);
	shell->pbuffer = shell->buffer + datarestlen;
	*shell->pbuffer = '\0';
	ncot_shell_push_command(context, command);
	res = ncot_shell_handle_command(context, command);
/*	DPRINTF(shell->writefd, "      p: 0x%0x\n", p);
	DPRINTF(shell->writefd, "     p0: 0x%0x\n", p0);
	DPRINTF(shell->writefd, " buffer: 0x%0x\n", shell->buffer);
	DPRINTF(shell->writefd, "command: %s\n", command);
	DPRINTF(shell->writefd, " buffer: 0x%0x\n", shell->buffer);
	DPRINTF(shell->writefd, "pbuffer: 0x%0x\n", shell->pbuffer);
	ncot_log_hex("shell->buffer", shell->buffer, p0 - shell->buffer);
	ncot_log_hex("buffer", shell->buffer, strlen(shell->buffer));
	ncot_log_hex("command", command, strlen(command));*/
	free(command);
	return res;
}


/** Depending on the shell type read in up to NCOT_SHELL_BUFLEN
 * bytes. Don't care when there are more bytes left to read, as we get
 * called again by our select loop */
int
ncot_shell_read_input(struct ncot_context *context)
{
	struct ncot_shell *shell;
	int res;
	if (!context) return -1;
	if (!context->shell) return -1;
	if (!context->shell->pbuffer) return -1;

	shell = context->shell;
	if (shell->type == NCOT_SHELL_TYPE_TTY)
		res = read(shell->readfd, shell->pbuffer, NCOT_SHELL_BUFLEN - (shell->pbuffer - shell->buffer));
	if (shell->type == NCOT_SHELL_TYPE_REMOTE)
#ifdef _WIN32
		res = recv(shell->readfd, shell->pbuffer, NCOT_SHELL_BUFLEN - (shell->pbuffer - shell->buffer), 0);
#else
		res = recv(shell->readfd, shell->pbuffer, NCOT_SHELL_BUFLEN - (shell->pbuffer - shell->buffer), MSG_DONTWAIT);
#endif
	if (res > 0) {
		shell->pbuffer += res;
		res = ncot_shell_handle_buffer(context);
		return res;
	}
	if (res == 0)
		return -1; /* TODO: How to handle EOF ?*/
	if (res < 0)
		return -1; /* TODO: Handle error ?*/
}

void
ncot_shell_print_prompt(struct ncot_shell *shell)
{
	char *remote = "";
	if (shell->isremote) remote="remote "; else remote = "";
	if (shell->incommand) {
		DPRINTF(shell->writefd, ANSI_COLOR_GREEN"%s%s%s%s", remote, shell->interactivetext, shell->promptinteractive, shell->promptend);
	} else {
		DPRINTF(shell->writefd, "%s%s%s", remote, shell->prompt, shell->promptend);
	}
}

struct ncot_shell*
ncot_shell_new()
{
	struct ncot_shell *shell;
	shell = calloc(1, sizeof(struct ncot_shell));
	return shell;
}

void
ncot_shell_init(struct ncot_shell *shell)
{
	if (shell) {
		shell->prompt = DEFAULT_SHELLPROMPT_START;
		shell->promptinteractive = DEFAULT_SHELLPROMPT_INTERACTIVE;
		shell->promptend = DEFAULT_SHELLPROMPT_END;
		shell->readfd = STDIN_FILENO;
		shell->writefd = STDOUT_FILENO;
		shell->pbuffer = shell->buffer;
		shell->type = NCOT_SHELL_TYPE_TTY;
	} else {
		NCOT_LOG_WARNING("Invalid shell argument passed to ncot_shell_init\n");
	}
}

void
ncot_shell_free(struct ncot_shell **pshell) {
	struct ncot_shell *shell;
	if (pshell) {
		shell = *pshell;
		if (shell) {
			free(shell);
			*pshell = NULL;
		} else
			NCOT_LOG_ERROR("Invalid shell argument\n");
	} else
		NCOT_LOG_ERROR("Invalid argument (*shell)\n");
}

void
ncot_shell_print_hexdump (struct ncot_shell *shell, void *addr, int len)
{
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char*)addr;
	int fd = shell->writefd;

	if (len < 0) {
		NCOT_LOG_INFO_BUFFERED("ncot_shell_print_hexdump: NEGATIVE LENGTH: %i\n", len);
		return;
	}

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				DPRINTF(fd, "  %s\n", buff);

			// Output the offset.
			DPRINTF(fd, "  %04x ", i);
		}

		// Now the hex code for the specific character.
		DPRINTF(fd, " %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		DPRINTF(fd, "   ");
		i++;
	}

	// And print the final ASCII bit.
	DPRINTF(fd, "  %s\n", buff);
}

void
ncot_shell_handle_hexdump(struct ncot_context *context, char *command, char *base)
{
	struct ncot_shell *shell;
	char *token;
	int valid = 0;
	shell = context->shell;
	token = strtok(NULL, " ");
	if (token) {
		ncot_shell_print_hexdump(shell, token, strlen(token));
	} else {
		DPRINTF(shell->writefd, "nothing specified\n");
	}
}

