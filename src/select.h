#ifndef _NCOT_SELECT_H_
#define _NCOT_SELECT_H_

#include <sys/types.h>

#include "context.h"

int ncot_set_fds(struct ncot_context *context, fd_set *rfds, fd_set *wfds);
int ncot_process_fd(struct ncot_context *context, int r, fd_set *rfds, fd_set *wfds);
int ncot_init_poll(struct ncot_context *context, struct ssh_event_struct *event);

#endif
