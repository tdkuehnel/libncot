#include "autoconfig.h"

#include <gnutls/gnutls.h>

#include "log.h"
#include "init.h"
#include "context.h"

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
	gnutls_global_set_log_level(GNUTLS_LOG_LEVEL);
	gnutls_global_set_log_function(print_logs);

}

void ncot_done()
{
	gnutls_global_deinit();
	ncot_log_done();
}

/*	node = ncot_node_new();
	if (node) {
		ncot_node_init(node);
		str = NULL;
		uuid_export(node->uuid, UUID_FMT_STR, &str, NULL);
		NCOT_LOG_INFO("Node created with uuid: %s \n", str);

	} else {
		NCOT_LOG_WARNING("unable to create ncot node.");
	}
*/
	/* main initialization ends here */

// GnuTLS will call this function whenever there is a new debugging log message.
void print_logs(int level, const char* msg)
{
	NCOT_LOG_INFO("GnuTLS [%d]: %s", level, msg);
}
