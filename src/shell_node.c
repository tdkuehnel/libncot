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

#include "shell.h"
#include "shell_connection.h"
#include "node.h"
#include "utlist.h"

void ncot_shell_node_create(struct ncot_context *context)
{
	struct ncot_node *node;
	const char *string = NULL;
	int ret;
	node = ncot_node_new();
	ncot_node_init(node);
	DL_APPEND(context->globalnodelist, node);
	ret = uuid_export(node->uuid, UUID_FMT_STR, &string, NULL);
	if (ret != UUID_RC_OK) {
		DPRINTF(context->shell->writefd, "unable to read uuid\n");
		return;
	}
	DPRINTF(context->shell->writefd, "New node with uuid: %s created.\n", string);

}

void ncot_shell_node_list(struct ncot_context *context, struct ncot_node *node)
{
	const char *string = NULL;
	struct ncot_connection *connection;
	uuid_export(node->uuid, UUID_FMT_STR, &string, NULL);
	DPRINTF(context->shell->writefd, "Node with uuid: %s\n", string);
	connection = node->connections;
	if (!connection) DPRINTF(context->shell->writefd, "<no connections>\n");
	while (connection) {
		ncot_shell_connection_list(context, connection);
		connection = connection->next;
	}
}

void ncot_shell_nodes_list(struct ncot_context *context)
{
	struct ncot_shell *shell;
	struct ncot_node *node;
	const char *string;
	char *token;
	int found = 0;

	shell = context->shell;
	node = context->globalnodelist;
	token = strtok(NULL, " ");
	if (!node) {
		DPRINTF(context->shell->writefd, "no nodes in global nodelist\n");
		return;
	}
	if (token) {
		/* Try to find a matching node */
		while (node && !found) {
			string = NULL;
			uuid_export(node->uuid, UUID_FMT_STR, &string, NULL);
			if (strncmp(token, string, strlen(token)) == 0) {
				found = 1;
				break;
			}
			node = node->next;
		}
		if (!found) {
			DPRINTF(shell->writefd, "unknown node %s... \n", token);
		} else {
			ncot_shell_node_list(context, node);
		}
	} else {
		/* Without a token list all nodes */
		while (node) {
			ncot_shell_node_list(context, node);
			node = node->next;
		}
	}
}

void
ncot_shell_node_handle_delete(struct ncot_context *context)
{
	struct ncot_shell *shell;
	struct ncot_node *node;
	const char *string;
	char *token;
	int found = 0;

	shell = context->shell;
	node = context->globalnodelist;
	token = strtok(NULL, " ");
	if (!node) {
		DPRINTF(context->shell->writefd, "no nodes in global nodelist\n");
		return;
	}
	if (token) {
		/* Try to find a matching node */
		while (node && !found) {
			string = NULL;
			uuid_export(node->uuid, UUID_FMT_STR, &string, NULL);
			if (strncmp(token, string, strlen(token)) == 0) {
				found = 1;
				break;
			}
			node = node->next;
		}
		if (!found) {
			DPRINTF(shell->writefd, "unknown node %s... \n", token);
		} else {
			DL_DELETE(context->globalnodelist, node);
			ncot_node_free(&node);
			DPRINTF(shell->writefd, "node %s deleted\n", string);
		}
	} else {
		/* Without a token display some info */
		DPRINTF(context->shell->writefd, "no node to delete specified\n");
	}
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
			ncot_shell_node_create(context);
			valid = 1;
		}
		if (!strcmp(token, "list")) {
			ncot_shell_nodes_list(context);
			valid = 1;
		}
		if (!strcmp(token, "delete")) {
			ncot_shell_node_handle_delete(context);
			valid = 1;
		}
		if (!valid)
			DPRINTF(shell->writefd, "unknown subcommand %s to command %s\n", token, base);
	} else {
		/* Default is listing the nodes */
		ncot_shell_nodes_list(context);
	}
}
