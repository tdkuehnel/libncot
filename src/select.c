#include "autoconfig.h"

#include <uuid.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "log.h"
#include "context.h"
#include "node.h"

/* Our main pselect loop has encountered some ready sds. Lets see how
 * we can handle that */
void
ncot_process_fd(struct ncot_context *context, int r, fd_set *rfds, fd_set *wfds)
{
 	/* Check if something is really happening */
	if (r <= 0) {
		NCOT_LOG_WARNING("ncot_process_fd: no ready fd indicated\n");
		return;
	}
	/* Doing it with the contexts lists. */
	struct ncot_connection *connection;
	struct ncot_node *node;
	int ret;
	/* First the connected ones */
	connection = context->connections_connected;
	while (connection) {
		if (FD_ISSET(connection->sd, rfds)) {
			ncot_connection_read_data(context, connection);
			NCOT_LOG_INFO("ncot_process_fd: connected connection is ready in rfds\n");
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
			NCOT_LOG_INFO("ncot_process_fd: listening connection was ready in rfds and is now connected\n");
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
			NCOT_LOG_INFO("ncot_process_fd: writing connection is ready in wfds\n");
			ncot_connection_write_data(context, connection);
		}
		connection = connection->next;
	}
}

int
ncot_set_fds(struct ncot_context *context, fd_set *rfds, fd_set *wfds)
{
	int maxfd = 0;
	struct ncot_connection *connection;
	/* First the connected ones.
	 *
	 * A connected connection is generally interested in incoming
	 * traffic. */
	connection = context->connections_connected;
	while (connection) {
		FD_SET(connection->sd, rfds);
		if (connection->sd > maxfd) maxfd = connection->sd;
		connection = connection->next;
	}
	/* Then the listening ones.
	 *
	 * Listening connections are only interested in incoming
	 * traffic.*/
	connection = context->connections_listen;
	while (connection) {
		FD_SET(connection->sd, rfds);
		if (connection->sd > maxfd) maxfd = connection->sd;
		connection = connection->next;
	}
	/* last the writing ones
	*
	* Writing connections are interested when there is some room
	* in the outgoing bandwidth */
	connection = context->connections_writing;
	while (connection) {
		FD_SET(connection->sd, wfds);
		if (connection->sd > maxfd) maxfd = connection->sd;
		connection = connection->next;
	}
	return maxfd;
}
