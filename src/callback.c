#include "callback.h"
#include "debug.h"
#include "error.h"

#include <poll.h>

int
ncot_cb_stdin_ready(socket_t fd, int revents, void *userdata)
{
	struct ncot_context *context;
	int res;

	if (!userdata) return -1;
	context = (struct ncot_context*) userdata;
	res = ncot_shell_read_input(context);
	if (!res) ncot_shell_print_prompt(context->shell);

}

int
ncot_cb_connection_ready(socket_t fd, int revents, void *userdata)
{
	struct ncot_cb_data *cbdata;
	struct ncot_context *context;
	struct ncot_connection *connection;

	if (!userdata) return -1;
	cbdata = (struct ncot_cb_data*) userdata;
	if (!cbdata->userdata1) return -1;
	if (!cbdata->userdata2) return -1;
	context = (struct ncot_context*) cbdata->userdata1;
	connection = (struct ncot_connection*) cbdata->userdata2;

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
