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
	struct ncot_node *globalnodelist;

	/* our dedicated control connection for the daemon, if any */
	struct ncot_connection *controlconnection;
};

struct ncot_context *ncot_context_new();
void ncot_context_init(struct ncot_context *context);
void ncot_context_free(struct ncot_context **context);

#endif
