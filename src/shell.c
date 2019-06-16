#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#ifdef _WIN32
#include <winsock2.h>
#include <windef.h>
#elif __unix__
#include <sys/select.h>
#include <sys/socket.h>
#endif

#include "shell.h"
#include "context.h"
#include "error.h"

#ifdef _WIN32
char string[2048];
char *stringptr = (char*)string;
int ret;
#define DPRINTF(fd, fmt, ...) {ret = sprintf(stringptr, fmt, ## __VA_ARGS__);if (ret > 0) write(fd, &string, ret);}
#else
#define DPRINTF(fd, fmt, ...) {dprintf(fd, fmt, ## __VA_ARGS__);}
#endif

#define NCOT_MAX_COMMAND_LEN 1024

void
ncot_shell_handle_identity(struct ncot_context *context, char *command, char *base)
{
	struct ncot_shell *shell;
	shell = context->shell;
}

void ncot_shell_node_list(struct ncot_context *context)
{
	struct ncot_node *node;
	node = context->globalnodelist;
	if (!node)
		DPRINTF(context->shell->writefd, "no nodes in global nodelist\n");

}

void
ncot_shell_handle_node(struct ncot_context *context, char *command, char *base)
{
	struct ncot_shell *shell;
	char *token;
	int valid = 0;
	shell = context->shell;
	token = strtok(NULL, " ");
	if (token) {
		if (!strcmp(token, "create")) {
			DPRINTF(shell->writefd, "create node\n");
			valid = 1;
		}
		if (!strcmp(token, "list")) {
			valid = 1;
			ncot_shell_node_list(context);
		}
		if (!strcmp(token, "delete")) {
			DPRINTF(shell->writefd, "delete node\n");
			valid = 1;
		}
		if (!valid)
			DPRINTF(shell->writefd, "unknown subcommand %s to command %s\n", token, base);
	} else {
		/* Default is listing the nodes */
		ncot_shell_node_list(context);
	}
}

void
ncot_shell_handle_connection(struct ncot_context *context, char *command, char *base)
{
	struct ncot_shell *shell;
	shell = context->shell;
}

void
ncot_shell_print_help(struct ncot_context *context, char *command, char *base)
{
	struct ncot_shell *shell;
	shell = context->shell;
	DPRINTF(shell->writefd, "Commands: identity\n");
	DPRINTF(shell->writefd, "          node\n");
	DPRINTF(shell->writefd, "          connection\n");
	DPRINTF(shell->writefd, "          quit\n");
	DPRINTF(shell->writefd, "          help\n");
}

int
ncot_shell_handle_command(struct ncot_context *context, char *command)
{
	struct ncot_shell *shell;
	char *token;
	int valid = 0;
	int ret = 0;
	shell = context->shell;
	token = strtok(command, " ");
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
		if (!strcmp(token, "connection")) {
			ncot_shell_handle_connection(context, command, token);
			valid = 1;
		}
		if (!strcmp(token, "help")) {
			ncot_shell_print_help(context, command, token);
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

int
ncot_shell_read_input(struct ncot_context *context)
{
	struct ncot_shell *shell;
	int res;
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
	DPRINTF(shell->writefd, "%s", shell->prompt);
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
		shell->prompt = DEFAULT_SHELLPROMPT;
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
