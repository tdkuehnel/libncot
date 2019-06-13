#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "shell.h"
#include "error.h"

int
ncot_shell_handle_buffer(struct ncot_shell *shell)
{
	/* TODO: handle the action */
	ncot_shell_print_prompt(shell);
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
