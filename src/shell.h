#ifndef _NCOT_SHELL_H_
#define _NCOT_SHELL_H_

#include "packet.h"
#include "context.h"

#include "log.h"

#ifdef _WIN32
#define DEFAULT_SHELLPROMPT_START "ncot"
#define DEFAULT_SHELLPROMPT_INTERACTIVE_START "ncot:"
#define DEFAULT_SHELLPROMPT_INTERACTIVE ":"
#define DEFAULT_SHELLPROMPT_END ">"
#else
#define DEFAULT_SHELLPROMPT_START ANSI_COLOR_GREEN"ncot"ANSI_COLOR_RESET
#define DEFAULT_SHELLPROMPT_INTERACTIVE_START ANSI_COLOR_GREEN"ncot:"ANSI_COLOR_RESET
#define DEFAULT_SHELLPROMPT_INTERACTIVE ANSI_COLOR_GREEN":"ANSI_COLOR_RESET
#define DEFAULT_SHELLPROMPT_END ANSI_COLOR_RED">"ANSI_COLOR_RESET
#endif

#define NCOT_SHELL_BUFLEN 2048
#define NCOT_SHELL_HISTORY_MAX_COMMANDS 128
#define NCOT_MAX_COMMAND_LEN 1024

#ifdef _WIN32
extern char* stringptr;
extern int ret;
#define DPRINTF(fd, fmt, ...) {ret = sprintf(stringptr, fmt, ## __VA_ARGS__);if (ret > 0) write(fd, &string, ret);}
#else
#define DPRINTF(fd, fmt, ...) {dprintf(fd, fmt, ## __VA_ARGS__);}
#endif

enum ncot_shell_type {
	NCOT_SHELL_TYPE_TTY,
	NCOT_SHELL_TYPE_REMOTE
};

struct ncot_command_line;
struct ncot_command_line {
	char* line;
	struct ncot_command_line *next;
	struct ncot_command_line *prev;
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
	char *promptend;
	char *promptinteractive;

	/* shell input buffer */
	char buffer[NCOT_SHELL_BUFLEN];
	char *pbuffer;

	/* We provide a struct ncot_packet for convenience */
	struct ncot_packet packet;
	/* This is for our (not yet implemented) history functionality */
	struct ncot_command_line *commandlines; /* Circular list of history commandlines */
	struct ncot_command_line *current; /* Current selected one */
	int commands; /* Convinience counter for len of history circular ringbuffer*/

        /* If nonzero we are currently awaiting read in user interaction */
	int incommand;

	/* Where to process further action */
	void (*proceed_command)(struct ncot_context *context, char *command);

	/* Interactive data */
	void *data;
	void *subdata;

	/* Remote shell ? */
	int isremote;

	/* Currently to display user interaction text */
	char interactivetext[NCOT_SHELL_BUFLEN];

        /* We hold a current node sometimes */
	struct ncot_node *currentnode;
};

struct ncot_shell *ncot_shell_new();
void ncot_shell_init(struct ncot_shell *shell);
void ncot_shell_free(struct ncot_shell **pshell);

int ncot_shell_handle_buffer(struct ncot_context *context);
int ncot_shell_read_input(struct ncot_context *context);
void ncot_shell_print_prompt(struct ncot_shell *shell);
void ncot_shell_print_help(struct ncot_context *context, char *command, char *base);
void ncot_shell_print_hexdump (struct ncot_shell *shell, void *addr, int len);

void ncot_shell_push_command(struct ncot_context *context, char *command);

void ncot_shell_handle_context(struct ncot_context *context, char *command, char *base);
void ncot_shell_handle_connection(struct ncot_context *context, char *command, char *base);
void ncot_shell_handle_identity(struct ncot_context *context, char *command, char *base);
void ncot_shell_handle_node(struct ncot_context *context, char *command, char *base);
void ncot_shell_handle_hexdump(struct ncot_context *context, char *command, char *base);

void ncot_shell_identity_list(struct ncot_context *context);
void ncot_shell_nodes_list(struct ncot_context *context);

void ncot_shell_reset(struct ncot_shell *shell);
void ncot_shell_handle_interaction(struct ncot_shell *shell, char *text, void (*proceed_command)(struct ncot_context *context, char *command), void *data);
#endif
