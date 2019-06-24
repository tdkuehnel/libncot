#ifndef _NCOT_SHELL_H_
#define _NCOT_SHELL_H_

#include "packet.h"
#include "context.h"
#include "log.h"

#define DEFAULT_SHELLPROMPT ANSI_COLOR_GREEN"ncot"ANSI_COLOR_RED">"ANSI_COLOR_RESET
#define NCOT_SHELL_BUFLEN 2048

enum ncot_shell_type {
	NCOT_SHELL_TYPE_TTY,
	NCOT_SHELL_TYPE_REMOTE
};

struct ncot_shell {
	/* For the interactive shell functionality we provide file
	 * descriptor/sockets */
	int readfd;
	int writefd;

	/* For now we handle file/socket descriptors differently for
	 * reading (is this really necessary or can read() do the
	 * trick?)
	 */
	enum ncot_shell_type type;

	/* shell prompt string */
	char *prompt;

	/* shell input buffer */
	char buffer[NCOT_SHELL_BUFLEN];
	char *pbuffer;

	/* We provide a struct ncot_packet for convenience */
	struct ncot_packet packet;
};

struct ncot_shell *ncot_shell_new();
void ncot_shell_init(struct ncot_shell *shell);
void ncot_shell_free(struct ncot_shell **pshell);

int ncot_shell_handle_buffer(struct ncot_context *context);
int ncot_shell_read_input(struct ncot_context *context);
void ncot_shell_print_prompt(struct ncot_shell *shell);
void ncot_shell_print_hexdump (struct ncot_shell *shell, void *addr, int len);

#endif
