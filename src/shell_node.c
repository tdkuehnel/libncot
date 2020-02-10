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

#ifdef HAVE_NETDB_H
#include <netdb.h>
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
ncot_shell_node_handle_listen_2(struct ncot_context *context, char *command)
{
	struct ncot_shell *shell;
	int port;
	int ret;
	shell = context->shell;
	/* See if we can use the data read from the user. For now we
	 * read in our port, too */
	if (command[0] == '\0') {
		ncot_shell_reset(shell);
		DPRINTF(shell->writefd, "command aborted.\n");
		return;
	}
	port = atoi(command);
	if (port < 1025 || port > 65535) {
		DPRINTF(shell->writefd, "invalid port number %d\n", port);
		ncot_shell_reset(shell);
		return;
	}
	ret = ncot_connection_listen(context, (struct ncot_connection*)shell->data, port);
	DPRINTF(shell->writefd, "listen operation returned %d.\n", ret);
	ncot_shell_reset(shell);
}

void
ncot_shell_node_handle_listen(struct ncot_context *context)
{
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
			DPRINTF(shell->writefd, "trying to make node %s listen\n", string);
		}
	} else {
		/* Without a token display current node if any */
		if (shell->currentnode) {
			string = NULL;
			uuid_export(shell->currentnode->uuid, UUID_FMT_STR, &string, NULL);
			DPRINTF(shell->writefd, "trying to make current node %s listen\n", string);
		} else {
			DPRINTF(context->shell->writefd, "no current node set and no node specified\n");
			return;
		}
	}
	/* Listen means we listen on one of our three connection
	 * ends. Make sure we only listen on one end (Does this
	 * restriction makes sense at all?) */
	connectionlist = node->connections;
	if (!connectionlist) {
		DPRINTF(context->shell->writefd, "ERROR: node %s has no connections, cannot listen.\n", string);
		return;
	}
	found = 0;
	while (connectionlist) {
		if (connectionlist->connection->type == NCOT_CONN_NODE && connectionlist->connection->status == NCOT_CONN_LISTEN) {
			found = 1;
			break;
		}
		connectionlist = connectionlist->next;
	}
	if (found) {
		DPRINTF(context->shell->writefd, "One connection already in listening state and only one in this state allowed at all, sorry.\n");
		return;
	} else {
		connectionlist = node->connections;
		found = 0;
		while (connectionlist) {
			if (connectionlist->connection->type == NCOT_CONN_NODE && connectionlist->connection->status == NCOT_CONN_INIT) {
				found = 1;
				break;
			}
			connectionlist = connectionlist->next;
		}
		if (found) {
			ncot_shell_handle_interaction(shell, "Enter Port to listen on (1025 - 65535)", ncot_shell_node_handle_listen_2, (void*)connectionlist->connection);
		} else {
			DPRINTF(context->shell->writefd, "No free connection available, cannot listen (Should never happen).\n", string);
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
	ncot_shell_reset(context->shell);
}

void
ncot_shell_node_handle_connect_2(struct ncot_context *context, char *command)
{
	struct ncot_shell *shell;
	shell = context->shell;
	/* See if we can use the data read from the user. For now we
	 * read in our port, too */
	if (command[0] == '\0') {
		ncot_shell_reset(shell);
		DPRINTF(shell->writefd, "command aborted.\n");
		return;
	}
	shell->subdata = malloc(strlen(command) + 1);
	strncpy(shell->subdata, command, strlen(command) + 1);
	ncot_shell_handle_interaction(shell, "Enter Port to connect to", ncot_shell_node_handle_connect_3, NULL);
}

void
ncot_shell_node_handle_disconnect(struct ncot_context *context)
{
	struct ncot_shell *shell;
	struct ncot_node *node;
	struct ncot_connection_list *connectionlist;
	const char *string;
	char *token;
	int found = 0;
	int connnum;
	int i;
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
			/* When we have a current node, use it and
			 * presume our token is the connection
			 * number */
			if (shell->currentnode) {
				/* Use token as connection number */
			} else {
				DPRINTF(shell->writefd, "unknown node %s and no current node set \n", token);
				return;
			}
		} else {
			token = strtok(NULL, " ");
			if (!token) {
				DPRINTF(context->shell->writefd, "Node found, but no connection number specified\n");
				return;
			}
		}
		DPRINTF(shell->writefd, "disconnecting node: %s\n", string);
		connnum = atoi(token);
		if (connnum < 1 || connnum > 3) {
			DPRINTF(context->shell->writefd, "invalid connection number specified (%d)\n", connnum);
			return;
		}
		connectionlist = node->connections;
		for (i=1; i<connnum; i++) {
			if (connectionlist->next) {
				connectionlist = connectionlist->next;
			} else {
				NCOT_LOG_ERROR("ncot_shell_handle_disconnect: invalid number of connections\n");
				return;
			}
		}
		if (connectionlist->connection->status != NCOT_CONN_CONNECTED && connectionlist->connection->status != NCOT_CONN_LISTEN) {
			DPRINTF(shell->writefd, "connection %d of node: %s neither connected nor listening, cannot disconnect\n", connnum, string);
			return;
		}
		ncot_connection_close(connectionlist->connection);
		DPRINTF(shell->writefd, "connection %d of node: %s disconnected\n", connnum, string);
	} else {
		DPRINTF(context->shell->writefd, "No node and connection number specified\n");
	}
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

/** We provide a schortcut to one selected node to operate on. You can
 * issue ncot:>node current 1a23 <enter> and when there is a node
 * which begins with 1a23, it will become the current one. When you
 * have set a current node, every node related command works on this
 * node without specifying its uuid further. It is shown with the
 * <info> command. */
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
		if (!strcmp(token, "listen")) {
			ncot_shell_node_handle_listen(context);
			valid = 1;
		}
		if (!strcmp(token, "delete")) {
			ncot_shell_node_handle_delete(context);
			valid = 1;
		}
		if (!strcmp(token, "disconnect")) {
			ncot_shell_node_handle_disconnect(context);
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
