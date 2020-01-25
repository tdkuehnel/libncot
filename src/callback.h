#ifndef _NCOT_CALLBACK_H_
#define _NCOT_CALLBACK_H_

#include <libssh/libssh.h>
#include "context.h"

/* Here we clearly work against the limit of a callback driven
   approach.  We not only need our context in a callback, we also need
   to provide information about which part of our context the callback
   should work on. So we could either pollute every single struct a
   callback could ever get hands on with a pointer to the context,
   where the context has already a pointer to the struct, so we
   introduce unnecessary redundancy. Many structs act like objects and
   can get instantiated multiple times easily. So blowing up our data
   structs with redundant iformation and wasting memory can not be
   our goal.
   So we introduce some runtime overhead in passing a
   struct as the void userdata parameter to our callbacks.
 */

struct ncot_cb_data {
	void *userdata1; /* Nearly always our context */
	void *userdata2; /* userdata of context to work on */
};

extern struct ssh_event_struct *mainloop;

int ncot_channel_write_wontblock_callback (ssh_session session, ssh_channel channel, size_t bytes, void *userdata);
int ncot_channel_data_callback (ssh_session session, ssh_channel channel, void *data, uint32_t len,	int is_stderr, void *userdata);
void ncot_channel_close_callback (ssh_session session, ssh_channel channel, void *userdata);
int ncot_cb_stdin_ready(socket_t fd, int revents, void *userdata);
int ncot_cb_connection_listen(socket_t fd, int revents, void *userdata);
int ncot_cb_connection_connect(socket_t fd, int revents, void *userdata);
int ncot_cb_connection_ready(socket_t fd, int revents, void *userdata);

#endif /* _NCOT_CALLBACK_H_ */
