#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "shell.h"
#include "error.h"

#define NCOT_MAX_COMMAND_LEN 1024

void
ncot_shell_handle_identity(struct ncot_shell *shell, char *command, char *base)
{
}

void
ncot_shell_handle_node(struct ncot_shell *shell, char *command, char *base)
{
	char *token;
	int valid = 0;
	token = strtok(NULL, " ");
	if (token) {
		if (!strcmp(token, "create")) {
			dprintf(shell->writefd, "create node\n");
			valid = 1;
		}
		if (!strcmp(token, "list")) {
			dprintf(shell->writefd, "list node\n");
			valid = 1;
		}
		if (!strcmp(token, "delete")) {
			dprintf(shell->writefd, "delete node\n");
			valid = 1;
		}
		if (!valid)
			dprintf(shell->writefd, "unknown subcommand %s to command %s\n", token, base);
	}
}

void
ncot_shell_handle_connection(struct ncot_shell *shell, char *command, char *base)
{
}

int
ncot_shell_handle_command(struct ncot_shell *shell, char *command)
{
	char *token;
	int valid = 0;
	token = strtok(command, " ");
	/*dprintf(shell->writefd, "token: %s\n", token);*/
	if (token) {
		if (!strcmp(token, "identity")) {
			ncot_shell_handle_identity(shell, command, token);
			valid = 1;
		}
		if (!strcmp(token, "node")) {
			ncot_shell_handle_node(shell, command, token);
			valid = 1;
		}
		if (!strcmp(token, "connection")) {
			ncot_shell_handle_connection(shell, command, token);
			valid = 1;
		}
		if (!valid)
			dprintf(shell->writefd, "unknown command %s\n", command);
	}
}

int
ncot_shell_handle_buffer(struct ncot_shell *shell)
{
	/* TODO: handle the action */
	char *p;
	char *p0;
	char *command;
	command = malloc(NCOT_MAX_COMMAND_LEN);
	/* Find the first lf */
	p = strchr(shell->buffer, '\n');
	if (p != NULL) {
		memcpy(command, shell->buffer, p - shell->buffer);
		command[p - shell->buffer] = '\0';
		p0 = strchr(shell->buffer, '\0');
		memmove(shell->buffer, p, (p0 - 1) - p);
		shell->pbuffer = shell->buffer + ((p0 - 1) - p);
		ncot_shell_handle_command(shell, command);
		dprintf(shell->writefd, "%s\n", command);
	}
	dprintf(shell->writefd, " buffer: 0x%0x\n", shell->buffer);
	dprintf(shell->writefd, "pbuffer: 0x%0x\n", shell->pbuffer);
	/*ncot_log_hex("shell->buffer", shell->buffer, p0 - shell->buffer);*/
	ncot_log_hex("buffer", shell->buffer, strlen(shell->buffer));
	ncot_log_hex("command", command, strlen(command));
	free(command);
	return 0;
}

int
ncot_shell_read_input(struct ncot_shell *shell)
{
	int res;
	if (shell->type == NCOT_SHELL_TYPE_TTY)
		res = read(shell->readfd, shell->pbuffer, NCOT_SHELL_BUFLEN - (shell->pbuffer - shell->buffer));
	if (shell->type == NCOT_SHELL_TYPE_REMOTE)
		res = recv(shell->readfd, shell->pbuffer, NCOT_SHELL_BUFLEN - (shell->pbuffer - shell->buffer), MSG_DONTWAIT);
	if (res > 0) {
		shell->pbuffer += res;
		ncot_shell_handle_buffer(shell);
		ncot_shell_print_prompt(shell);

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
	dprintf(shell->writefd, "%s", shell->prompt);
}

#define NCOT_READLINE_BUFSIZE 1024

char *ncot_read_line(void)
{
	int bufsize = NCOT_READLINE_BUFSIZE;
	int position = 0;
	char *buffer;
	int c;

	buffer = malloc(sizeof(char) * bufsize);
	RETURN_NULL_IF_NULL(buffer, "ncot_read_line: out of mem\n");

	while (1) {
		// Read a character
		c = getchar();

		// If we hit EOF, replace it with a null character and return.
		if (c == EOF || c == '\n') {
			buffer[position] = '\0';
			return buffer;
		} else {
			buffer[position] = c;
		}
		position++;

		// If we have exceeded the buffer, reallocate.
		if (position >= bufsize) {
			bufsize += NCOT_READLINE_BUFSIZE;
			buffer = realloc(buffer, bufsize);
			RETURN_NULL_IF_NULL(buffer, "ncot_read_line: out of mem\n");
		}
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
