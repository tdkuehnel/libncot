#include "autoconfig.h"

#include <uuid.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "log.h"
#include "ncot.h"
#include "context.h"

/* Our main pselect loop has encountered some ready sds. Lets see how
 * we can handle that */
void
ncot_process_fd(struct ncot_context *context, int r, fd_set *rfds, fd_set *wfds)
{
	/* Check if something is really happening */
	if (r > 0) {
		/* Before we have our lists for pending and closed
		 * connections, we do it by hand */
		if (context->controlconnection->status == NCOT_CONN_LISTEN) {
			if (FD_ISSET(context->controlconnection->sd, rfds)) {
				NCOT_LOG_INFO("ncot_process_fd: controlconnection is ready in rfds\n");
				ncot_connection_accept(context, context->controlconnection);
			}
		}
		if (context->controlconnection->status == NCOT_CONN_CONNECTED) {
			if (FD_ISSET(context->controlconnection->sd, rfds)) {
				/* assuming not 0 means fd is in set */
				ncot_connection_read_data(context->controlconnection);
			}
			if (FD_ISSET(context->controlconnection->sd, wfds)) {
				/* assuming not 0 means fd is in set */
				ncot_connection_write_data(context->controlconnection);
			}
		}
		if (FD_ISSET(context->controlconnection->sd, rfds)) {
			NCOT_LOG_INFO("ncot_process_fd: controlconnection->sd in rfds\n");
		}
		if (FD_ISSET(context->controlconnection->sd, wfds)) {
			NCOT_LOG_INFO("ncot_process_fd: controlconnection->sd in wfds\n");
		}


	} else {
		NCOT_LOG_WARNING("ncot_process_fd: no ready fd indicated\n");
	}
}

void
ncot_set_fds(struct ncot_context *context, fd_set *rfds, fd_set *wfds)
{
	if (context->controlconnection->status == NCOT_CONN_LISTEN ||
		context->controlconnection->status == NCOT_CONN_CONNECTED) {
		FD_SET(context->controlconnection->sd, rfds);
		/* As we have nothing to write yet, don't put the sd
		in the wfds set, or our pselect loop will run
		away. Better only include a connections sd in the wfds
		set when we want to actually sent data, so that our
		loop iterates when there is "some place in the
		bandwidth of the outgoing connection" where we can
		actually put some data to send in.*/
		/*sent FD_SET(context->controlconnection->sd,wfds); */
	}
}

ncot_identity_t *ncot_identity_new()
{
	ncot_identity_t *identity;
	identity = calloc(1, sizeof(ncot_identity_t));
	return identity;
}

void ncot_identity_init(ncot_identity_t *identity) {
	if (identity) {
		uuid_create(&identity->uuid);
		uuid_make(identity->uuid, UUID_MAKE_V1);
	} else {
		NCOT_LOG_WARNING("Invalid identity passed to ncot_identity_init\n");
	}
}

void ncot_identity_free(ncot_identity_t **pidentity) {
	ncot_identity_t *identity;
	if (pidentity) {
		identity = *pidentity;
		if (identity) {
			if (identity->uuid) uuid_destroy(identity->uuid);
			free(identity);
			*pidentity = NULL;
		} else
			NCOT_LOG_ERROR("Invalid ncot_identity\n");
	} else
		NCOT_LOG_ERROR("Invalid argument (*identity)\n");
}

void ncot_init()
{
	ncot_log_init(NCOT_LOG_LEVEL_WARNING);
	/* During tests we like to log to different files which is set
	 * up later by ncot_log_set_logfile. This startup message
	 * pollutes the main test log file. Alternatively we could
	 * find a way to provide distinctive instance information to
	 * show up to make the message useful.*/

	/*NCOT_LOG_INFO("%s\n", PACKAGE_STRING);*/
	gnutls_global_init();

}

void ncot_done()
{
	gnutls_global_deinit();
	ncot_log_done();
}
