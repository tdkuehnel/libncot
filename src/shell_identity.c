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

void ncot_shell_identity_list(struct ncot_context *context)
{
	const char *string = NULL;
	int ret;
	if (!context->identity) {
		DPRINTF(context->shell->writefd, "no identity set\n");
		return;
	}
	ret = uuid_export(context->identity->uuid, UUID_FMT_STR, &string, NULL);
	if (ret != UUID_RC_OK) {
		DPRINTF(context->shell->writefd, "unable to read uuid\n");
		return;
	}
	DPRINTF(context->shell->writefd, "Identity with uuid: %s\n%s\n%s\n", string, context->identity->name, context->identity->avatar);
}

void ncot_shell_identity_create(struct ncot_context *context)
{
	const char *string = NULL;
	int ret;
	if (!context->identity) {
		context->identity = ncot_identity_new();
		ncot_identity_init(context->identity);
		ret = uuid_export(context->identity->uuid, UUID_FMT_STR, &string, NULL);
		DPRINTF(context->shell->writefd, "Identity with uuid: %s created\n", string);
		return;
	} else {
		ret = uuid_export(context->identity->uuid, UUID_FMT_STR, &string, NULL);
		DPRINTF(context->shell->writefd, "There is an Identity with uuid: %s already. Delete if first.\n", string);
	}

}

void ncot_shell_identity_delete(struct ncot_context *context)
{
	const char *string = NULL;
	int ret;
	if (context->identity) {
		ret = uuid_export(context->identity->uuid, UUID_FMT_STR, &string, NULL);
		ncot_identity_free(&context->identity);
		DPRINTF(context->shell->writefd, "Identity with uuid: %s deleted\n", string);
		return;
	} else {
		DPRINTF(context->shell->writefd, "no identity set\n");
	}

}

void ncot_shell_identity_handle_name(struct ncot_context *context)
{
	struct ncot_shell *shell;
	const char *string = NULL;
	char *token;
	int valid = 0;
	int ret;
	shell = context->shell;
	token = strtok(NULL, " ");
	ret = uuid_export(context->identity->uuid, UUID_FMT_STR, &string, NULL);
	if (token) {
		strncpy(context->identity->name, token, NCOT_IDENTITY_NAME_LENGTH);
		context->identity->name[NCOT_COMMAND_LINE_LENGTH] = '\0';
		DPRINTF(context->shell->writefd, "Identity %s: name set to %s\n", string, context->identity->name);
	} else {
		/* Default is showing the name */
		if (context->identity->name[0] != '\0') {
			DPRINTF(context->shell->writefd, "Identity %s: %s\n", string, context->identity->name);
		} else {
			DPRINTF(context->shell->writefd, "Identity %s: %s\n", string, "<empty>");
		}
	}
}

void ncot_shell_identity_handle_avatar(struct ncot_context *context)
{
	struct ncot_shell *shell;
	const char *string = NULL;
	char *token;
	int valid = 0;
	int ret;
	int fd;
	int i;
	shell = context->shell;
	token = strtok(NULL, " ");
	ret = uuid_export(context->identity->uuid, UUID_FMT_STR, &string, NULL);
	if (token) {
		fd = open(token, O_RDONLY);
		if (fd <= 0) {
			DPRINTF(context->shell->writefd, "Cannot open %s to read avatar from\n", token);
			return;
		}
		ret = read(fd, context->identity->avatar, NCOT_IDENTITY_AVATAR_LENGTH - 1);
		if (ret >= 0) {
			context->identity->avatar[ret] = '\0';
			/* Remove unprintable ascii characters */
			for (i=0; i < ret; i++) {
				if (context->identity->avatar[i] != 0x0a)
					if ((context->identity->avatar[i] < 0x20) || (context->identity->avatar[i] > 0x7e))
						context->identity->avatar[i] = '.';
			}
			DPRINTF(context->shell->writefd, "Identity %s:\n%s\n", string, context->identity->avatar);
		} else {
			DPRINTF(context->shell->writefd, "Error reading avatar from %s\n", token);
		}
		close(fd);
		return;
	} else {
		/* Default is showing the avatar */
		if (context->identity->avatar[0] != '\0') {
			DPRINTF(context->shell->writefd, "Identity %s:\n%s\n", string, context->identity->avatar);
		} else {
			DPRINTF(context->shell->writefd, "Identity %s: Avatar is <empty>\n", string);
		}
	}
}

void
ncot_shell_handle_identity(struct ncot_context *context, char *command, char *base)
{
	struct ncot_shell *shell;
	char *token;
	int valid = 0;
	shell = context->shell;
	token = strtok(NULL, " ");
	if (token) {
		if (!strcmp(token, "create")) {
			ncot_shell_identity_create(context);
			valid = 1;
		}
		if (!strcmp(token, "list")) {
			valid = 1;
			ncot_shell_identity_list(context);
		}
		if (!strcmp(token, "delete")) {
			ncot_shell_identity_delete(context);
			valid = 1;
		}
		if (!strcmp(token, "name")) {
			ncot_shell_identity_handle_name(context);
			valid = 1;
		}
		if (!strcmp(token, "avatar")) {
			ncot_shell_identity_handle_avatar(context);
			valid = 1;
		}
		if (!valid)
			DPRINTF(shell->writefd, "unknown subcommand %s to command %s\n", token, base);
	} else {
		/* Default is listing the nodes */
		ncot_shell_identity_list(context);
	}
}
