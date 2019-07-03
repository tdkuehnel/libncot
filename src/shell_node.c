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

#include <netdb.h>


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
	struct ncot_connection_list *connectionlist;
	uuid_export(node->uuid, UUID_FMT_STR, &string, NULL);
	DPRINTF(context->shell->writefd, "Node with uuid: %s\n", string);
	connectionlist = node->connections;
	if (!connectionlist) DPRINTF(context->shell->writefd, "<no connections>\n");
	while (connectionlist) {
		ncot_shell_connection_list(context, connectionlist->connection);
		connectionlist = connectionlist->next;
	}
	if (ncot_node_is_connected(node))
		DPRINTF(context->shell->writefd, "Node is connected.\n")
	else
		DPRINTF(context->shell->writefd, "Node is not connected.\n");

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
ncot_shell_node_handle_connect_3(struct ncot_context *context, char *command)
{
	struct ncot_shell *shell;
	struct addrinfo hints;
	struct addrinfo *result;
	int ret;
	shell = context->shell;
	/* See if we can use the data read from the user. For now we
	 * read in our port, too */
	if (command[0] == '\0') {
		shell->incommand = 0;
		shell->proceed_command = NULL;
		shell->data = NULL;
		shell->interactivetext[0] = '\0';
		free(shell->subdata);
		DPRINTF(shell->writefd, "command aborted.\n");
		return;
	}
	ret = ncot_connection_connect(context, (struct ncot_connection*)shell->data, command, (char*)shell->subdata);
	DPRINTF(shell->writefd, "connect operation returned %d\n", ret);
	shell->incommand = 0;
	shell->proceed_command = NULL;
	shell->data = NULL;
	shell->interactivetext[0] = '\0';
}

void
ncot_shell_node_handle_connect_2(struct ncot_context *context, char *command)
{
	struct ncot_shell *shell;
	shell = context->shell;
	/* See if we can use the data read from the user. For now we
	 * read in our port, too */
	if (command[0] == '\0') {
		shell->incommand = 0;
		shell->proceed_command = NULL;
		shell->data = NULL;
		shell->interactivetext[0] = '\0';
		DPRINTF(shell->writefd, "command aborted.\n");
		return;
	}
	shell->subdata = malloc(strlen(command) + 1);
	strncpy(shell->subdata, command, strlen(command) + 1);
	ncot_shell_handle_interaction(shell, "Enter Port to connect to", ncot_shell_node_handle_connect_3, NULL);
}

void
ncot_shell_node_handle_connect(struct ncot_context *context)
{
	/* TODO: wrong code */
	struct ncot_shell *shell;
	struct ncot_node *node;
	struct ncot_connection_list *connectionlist;
	const char *string;
	char *token;
	int found = 0;
	shell = context->shell;
	node = context->globalnodelist;
	token = strtok(NULL, " ");
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
			return;
		} else {
			DPRINTF(shell->writefd, "connect with node: %s\n", string);
		}
	} else {
		/* Without a token display current node if any */
		if (shell->currentnode) {
			string = NULL;
			uuid_export(shell->currentnode->uuid, UUID_FMT_STR, &string, NULL);
			DPRINTF(shell->writefd, "connect with node: %s\n", string);
		} else {
			DPRINTF(context->shell->writefd, "no current node set and no node specified\n");
			return;
		}
	}
	/* Let's find out if we have a dangling connection which we
	 * can use for the connect operation */
	connectionlist = node->connections;
	if (!connectionlist) {
		DPRINTF(context->shell->writefd, "ERROR: node %s has no connections, cannot connect.\n", string);
		return;
	}
	found = 0;
	while (connectionlist) {
		if (connectionlist->connection->type == NCOT_CONN_NODE && connectionlist->connection->status == NCOT_CONN_INIT) {
			found = 1;
			break;
		}
		connectionlist = connectionlist->next;
	}
	if (found) {
		ncot_shell_handle_interaction(shell, "Enter IP Address to connect to", ncot_shell_node_handle_connect_2, (void*)connectionlist->connection);
	} else {
		DPRINTF(context->shell->writefd, "No free connection available, cannot connect.\n", string);
	}
}

void
ncot_shell_node_handle_current(struct ncot_context *context)
{
	struct ncot_shell *shell;
	struct ncot_node *node;
	const char *string;
	char *token;
	int found = 0;
	shell = context->shell;
	node = context->globalnodelist;
	token = strtok(NULL, " ");
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
			return;
		} else {
			shell->currentnode = node;
			DPRINTF(shell->writefd, "current node set to %s\n", string);
		}
	} else {
		/* Without a token display current node if any */
		if (shell->currentnode) {
			string = NULL;
			uuid_export(shell->currentnode->uuid, UUID_FMT_STR, &string, NULL);
			DPRINTF(shell->writefd, "current node is %s... \n", string);
		} else {
			DPRINTF(context->shell->writefd, "no current node set\n");
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
		if (!strcmp(token, "current")) {
			ncot_shell_node_handle_current(context);
			valid = 1;
		}
		if (!strcmp(token, "connect")) {
			ncot_shell_node_handle_connect(context);
			valid = 1;
		}
		if (!valid)
			DPRINTF(shell->writefd, "unknown subcommand %s to command %s\n", token, base);
	} else {
		/* Default is listing the nodes */
		ncot_shell_nodes_list(context);
	}
}
