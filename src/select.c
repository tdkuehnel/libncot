#include "autoconfig.h"

/*#include <uuid.h>*/
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <libssh/libssh.h>
#include <poll.h>

#define DEBUG 0
#include "debug.h"
#include "log.h"
#include "context.h"
#include "node.h"
#include "callback.h"

#undef DEBUG
#define DEBUG 1
/* Our main pselect loop has encountered some ready sds. Lets see how
 * we can handle that */
int
ncot_process_fd(struct ncot_context *context, int r, fd_set *rfds, fd_set *wfds)
{
	int res = 0;
 	/* Check if something is really happening */
	if (r <= 0) {
		NCOT_LOG_WARNING("ncot_process_fd: no ready fd indicated\n");
		return res;
	}
	/* Doing it with the contexts lists. */
	struct ncot_connection *connection;
	struct ncot_connection *connectionnext;
	struct ncot_node *node;
	int ret;
	/* First the closing ones */
	connection = context->connections_closing;
	while (connection) {
		connection = connection->next;
	}

        /* Second the connected ones */
	connection = context->connections_connected;
	while (connection) {
		if (FD_ISSET(connection->sd, rfds)) {
			NCOT_DEBUG("ncot_process_fd: connected connection is ready in rfds\n");
			/* recv 0 bytes means orderly peer shut down,
			 * so react on it accordingly */
			switch (connection->status) {
			case NCOT_CONN_ACCEPTED:
				
				break;
			case NCOT_CONN_CONNECTED:
				if (ncot_connection_read_data(context, connection) == 0) {
					connectionnext = connection->next;
					ncot_context_dequeue_connection_connected(context, connection);
					ncot_context_enqueue_connection_closing(context, connection);
					connection->status = NCOT_CONN_CLOSING;
					NCOT_DEBUG("ncot_process_fd: remote connection closing\n");
					connection = connectionnext;
					continue;
				}
				while (ncot_connection_process_data(context, connection) > 0) {
					NCOT_DEBUG("ncot_process_fd: packet processed\n");
					break;
				}
			}
		}
		connection = connection->next;
	}
	/* Then the listening ones */
	connection = context->connections_listen;
	while (connection) {
		if (FD_ISSET(connection->sd, rfds)) {
			ret = ncot_connection_accept(context, connection);
			if (ret != 0) {
				NCOT_LOG_ERROR("ncot_process_fd: listen connection cannot accept\n");
				connection = connection->next;
				continue;
			}
			NCOT_DEBUG("ncot_process_fd: listening connection was ready in rfds and is now connected\n");
			node = ncot_context_get_node_by_connection(context, connection);
			if (node) {
				ncot_node_authenticate_peer(node, connection);
			} else {
				if (context->controlconnection == connection) {
					/* ncot_context_controlconnection_authenticate(context, connection); */
					ret = ncot_connection_authenticate_client(connection);
					/* We need to take appropriate
					 * action when authentication
					 * fails and set the
					 * connection into the listen
					 * state again maybe */
				} else {
					NCOT_LOG_WARNING("ncot_process_fd: node and/or connection list inconsistency\n");
				}
			}
		}
		connection = connection->next;
	}
	/* last the writing ones */
	connection = context->connections_writing;
	while (connection) {
		if (FD_ISSET(connection->sd, wfds)) {
			NCOT_DEBUG("ncot_process_fd: writing connection is ready in wfds\n");
			ncot_connection_write_data(context, connection);
		}
		connection = connection->next;
	}
	/* look at shells fd */
	if (context->shell) {
		if (FD_ISSET(context->shell->readfd, rfds)) {
			res = ncot_shell_read_input(context);
			if (!res)
				ncot_shell_print_prompt(context->shell);
		}
	}
	return res;
}

int
ncot_init_poll(struct ncot_context *context, struct ssh_event_struct *event)
{
	/* In interactive mode we include stdin */
	if (context->arguments) {
		if (context->arguments->interactive) {
			return ssh_event_add_fd(event, STDIN_FILENO, POLLIN, ncot_cb_stdin_ready, context);
		}
	}
}

#ifdef DEBUG
#undef DEBUG
#define DEBUG 0
#endif
int
ncot_set_fds(struct ncot_context *context, fd_set *rfds, fd_set *wfds)
{
	int maxfd = 0;
	struct ncot_connection *connection;
	/* First the connected ones.
	 *
	 * A connected connection is generally interested in incoming
	 * traffic. */
	NCOT_DEBUG("ncot_set_fds: 1\n");
	connection = context->connections_connected;
	NCOT_DEBUG("ncot_set_fds: 2\n");
	while (connection) {
		connection->sd = ssh_bind_get_fd(connection->sshbind);
		FD_SET(connection->sd, rfds);
		if (connection->sd > maxfd) maxfd = connection->sd;
		connection = connection->next;
	}
	NCOT_DEBUG("ncot_set_fds: 3\n");
	/* Then the listening ones.
	 *
	 * Listening connections are only interested in incoming
	 * traffic.*/
	connection = context->connections_listen;
	NCOT_DEBUG("ncot_set_fds: 4\n");
	while (connection) {
 		connection->sd = ssh_bind_get_fd(connection->sshbind);
		FD_SET(connection->sd, rfds);
		if (connection->sd > maxfd) maxfd = connection->sd;
		connection = connection->next;
	}
	NCOT_DEBUG("ncot_set_fds: 5\n");
	/* last the writing ones
	*
	* Writing connections are interested when there is some room
	* in the outgoing bandwidth */
	NCOT_DEBUG("ncot_set_fds: 6\n");
	connection = context->connections_writing;
	NCOT_DEBUG("ncot_set_fds: 7\n");
	while (connection) {
 		connection->sd = ssh_bind_get_fd(connection->sshbind);
		FD_SET(connection->sd, wfds);
		if (connection->sd > maxfd) maxfd = connection->sd;
		connection = connection->next;
	}
	/* In interactive mode we include stdin */
	NCOT_DEBUG("ncot_set_fds: 8\n");
	if (context->arguments) {
		if (context->arguments->interactive) {
			FD_SET(STDIN_FILENO, rfds);
			if (STDIN_FILENO > maxfd)
				maxfd = STDIN_FILENO;
		}
	}
	NCOT_DEBUG("ncot_set_fds: 9\n");
	return maxfd;
}
