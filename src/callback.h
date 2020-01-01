#ifndef _NCOT_CALLBACK_H_
#define _NCOT_CALLBACK_H_

#include <libssh/libssh.h>
#include "context.h"

struct ncot_cb_data {
	void *userdata1;
	void *userdata2;
};

int ncot_cb_stdin_ready(socket_t fd, int revents, void *userdata);

#endif /* _NCOT_CALLBACK_H_ */
