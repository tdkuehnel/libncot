#include "callback.h"
#include "debug.h"
#include "error.h"

#include <poll.h>

/* The one and only */
/* struct ssh_event_struct *mainloop; */

int
ncot_cb_stdin_ready(socket_t fd, int revents, void *userdata)
{
	struct ncot_context *context;
	int res;

	if (!userdata) return -1;
	context = (struct ncot_context*) userdata;
	res = ncot_shell_read_input(context);
	if (!res)
		ncot_shell_print_prompt(context->shell);
	else
		context->terminate = 1;
}

int
ncot_cb_connection_connect(socket_t fd, int revents, void *userdata)
{
	struct ncot_connection *connection;
	int r;

	if (!userdata) return -1;
	connection = (struct ncot_connection*) userdata;
 	if (revents & POLLIN &&!( revents & POLLOUT))
		NCOT_LOG_INFO("ncot_cb_connection_connect: called with POLLIN\n");
	if (!(revents & POLLIN) && revents & POLLOUT)
		NCOT_LOG_INFO("ncot_cb_connection_connect: called with POLLOUT\n");
	if (revents & POLLIN && revents & POLLOUT)
		NCOT_LOG_INFO("ncot_cb_connection_connect: called with POLLIN, POLLOUT\n");
}

/* int */
/* ncot_cb_connection_ready(socket_t fd, int revents, void *userdata) */
/* { */
/* 	struct ncot_connection *connection; */
/* 	int r; */

/* 	if (!userdata) return -1; */
/* 	connection = (struct ncot_connection*) userdata; */
/* 	if (revents & POLLIN &&!( revents & POLLOUT)) */
/* 		NCOT_LOG_INFO("ncot_cb_connection_connect: called with POLLIN\n"); */
/* 	if (!(revents & POLLIN) && revents & POLLOUT) */
/* 		NCOT_LOG_INFO("ncot_cb_connection_connect: called with POLLOUT\n"); */
/* 	if (revents & POLLIN && revents & POLLOUT) */
/* 		NCOT_LOG_INFO("ncot_cb_connection_connect: called with POLLIN, POLLOUT\n"); */
/* } */

int
ncot_cb_connection_listen(socket_t fd, int revents, void *userdata)
{
	struct ncot_connection *connection;
	int r;

	if (!userdata) return -1;
	connection = (struct ncot_connection*) userdata;
	NCOT_LOG_INFO("ncot_cb_connection_listen: called\n");
	if (!ssh_event_remove_fd(connection->context->mainloop, connection->sd) == SSH_OK) {
 		NCOT_LOG_ERROR("ncot_cb_connection_listen: unable to remove listen fd\n");
		return NCOT_FAILURE;
	}
	if (!ncot_connection_accept(connection->context, connection) == NCOT_OK) {
 		NCOT_LOG_ERROR("ncot_cb_connection_listen: ncot_connection_accept failed\n");
		return NCOT_FAILURE;
	} else {
		NCOT_LOG_INFO("ncot_cb_connection_listen: returning OK\n");
		return NCOT_OK;
	}
}

#ifndef DEBUG
#undef DEBUG
#define DEBUG 1
#endif

int
ncot_cb_connection_ready(socket_t fd, int revents, void *userdata)
{
	struct ncot_cb_data *cbdata;
	struct ncot_context *context;
	struct ncot_connection *connection;

	if (!userdata) return -1;
	connection = (struct ncot_connection*) userdata;
	context = (struct ncot_context*) connection->context;

 	if (revents & POLLIN &&!( revents & POLLOUT))
		NCOT_LOG_INFO("ncot_cb_connection_ready: called with POLLIN\n");
	if (!(revents & POLLIN) && revents & POLLOUT)
		NCOT_LOG_INFO("ncot_cb_connection_ready: called with POLLOUT\n");
	if (revents & POLLIN && revents & POLLOUT)
		NCOT_LOG_INFO("ncot_cb_connection_ready: called with POLLIN, POLLOUT\n");
	if (revents & POLLIN) {
		if (ncot_connection_read_data(context, connection) == 0) {
			connection->status = NCOT_CONN_CLOSING;
		}
		while (ncot_connection_process_data(context, connection) > 0) {
			NCOT_DEBUG("ncot_cb_connection_ready: packet processed\n");
		}
	}
	if (revents & POLLOUT) {
		ncot_connection_write_data(context, connection);
	}
	if (revents & POLLHUP) {
		NCOT_LOG_INFO("ncot_cb_connection_ready: POLLHUP occured\n");
	}
	if (revents & POLLERR) {
		NCOT_LOG_INFO("ncot_cb_connection_ready: POLLERR occured\n");
	}
	if (revents & POLLNVAL) {
		NCOT_LOG_INFO("ncot_cb_connection_ready: POLLNVAL occured\n");
	}
	return NCOT_OK;
}
