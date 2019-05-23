#ifndef NCOT_CONTEXT_H
#define NCOT_CONTEXT_H

#include <stdio.h>

struct ncot_context;

/*#include "helper.h"
  #include "command.h"
  #include "process.h"
  #include "pipe.h"
  #include "config.h"
*/

#include "log.h"
#include "arg.h"
#include "connection.h"

struct ncot_context {

	/* ncotconfig *config; */
	struct ncot_arguments *arguments;

	/* global main stuff */

	/* We maintain a list of our nodes which may take part in
	 * the circle of trusts */
	struct ncot_node *globalnodelist;

	/* Our dedicated control connection for the daemon, if any */
	struct ncot_connection *controlconnection;

	/* We need lists for our connections in the different
	 * connection states */

	/* Connected connections may receive data, and may be in the
	 * process of sending data. Should be in rfds and may be in wfds */
	struct ncot_connection *connections_connected;

	/* Listen connections just listen, waiting for a peer to
	 * connect. They are in rfds. */
	struct ncot_connection *connections_listen;

	/* Closed connections are just closed, not connected. They are
	 * available for reuse and in neither of the fds sets. */
	struct ncot_connection *connections_closed;

	/* Connections in the following list are in a writing process
	 * of something, they are connected and in the wfds set,
	 * possibly in the rfds set, too. */
	struct ncot_connection *connections_writing;
};

struct ncot_context *ncot_context_new();
void ncot_context_init(struct ncot_context *context);
void ncot_context_free(struct ncot_context **context);

void ncot_context_enqueue_connection_connected(struct ncot_context *context, struct ncot_connection *connection);
void ncot_context_enqueue_connection_listen(struct ncot_context *context, struct ncot_connection *connection);
void ncot_context_enqueue_connection_closed(struct ncot_context *context, struct ncot_connection *connection);
void ncot_context_enqueue_connection_writing(struct ncot_context *context, struct ncot_connection *connection);

void ncot_context_dequeue_connection_connected(struct ncot_context *context, struct ncot_connection *connection);
void ncot_context_dequeue_connection_listen(struct ncot_context *context, struct ncot_connection *connection);
void ncot_context_dequeue_connection_closed(struct ncot_context *context, struct ncot_connection *connection);
void ncot_context_dequeue_connection_writing(struct ncot_context *context, struct ncot_connection *connection);

#endif
