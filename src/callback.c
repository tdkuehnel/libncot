#include "callback.h"
#include "debug.h"
#include "error.h"

#include <poll.h>

/* The one and only */

#ifndef DEBUG
#undef DEBUG
#define DEBUG 1
#endif

void
ncot_channel_close_callback (ssh_session session, ssh_channel channel, void *userdata)
{
	struct ncot_connection *connection;

	if (!userdata) return;
	connection = (struct ncot_connection*)userdata;
	connection->terminate = 1;
	NCOT_LOG_INFO("ncot_channel_close_callback: called\n");
}

int
ncot_channel_data_callback (ssh_session session, ssh_channel channel, void *data, uint32_t len,	int is_stderr, void *userdata)
{
	int rc;
	/* char buf[1024]; */
	struct ncot_connection *connection;

	if (!userdata) return NCOT_ERROR;
	connection = (struct ncot_connection*)userdata;
	if (ncot_connection_read_data(connection->context, connection) == 0) {
		ncot_context_dequeue_connection_connected(connection->context, connection);
		ncot_context_enqueue_connection_closing(connection->context, connection);
		connection->status = NCOT_CONN_CLOSING;
		NCOT_DEBUG("ncot_channel_data_callback: remote connection closing\n");
		return 0;
	}
	NCOT_DEBUG("ncot_channel_data_callback: after ncot_connection_read_data\n");
	while (ncot_connection_process_data(connection->context, connection) > 0) {
		NCOT_DEBUG("ncot_channel_data_callback: packet processed\n");
		break;
	}
	NCOT_DEBUG("ncot_channel_data_callback: after ncot_connection_process_data\n");
	return 0;
	/* rc = ssh_channel_read_nonblocking(channel, (char*)&buf, 1024, 0); */
	/* if (rc == 0) { */
	/* 	NCOT_LOG_INFO("ncot_channel_data_callback: EOF detected\n"); */
	/* } else { */
	/* 	NCOT_LOG_INFO("ncot_channel_data_callback: %d bytes read atomically\n", rc); */
	/* 	buf[rc] = '\0'; */
	/* 	/\* printf("%s\n", buf); *\/ */
	/* 	NCOT_LOG_INFO("ncot_channel_data_callback: '%s'\n", buf); */
	/* 	return 5; */
	/* } */
}

int
ncot_channel_write_wontblock_callback (ssh_session session, ssh_channel channel, size_t bytes, void *userdata)
{
	NCOT_LOG_INFO("ncot_channel_write_wontblock_callback: called\n");
}

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

