#ifndef NCOT_CONTEXT_H
#define NCOT_CONTEXT_H

#include <stdio.h>

struct ncotcontext;

/*#include "helper.h"
#include "command.h"
#include "process.h"
#include "pipe.h"
#include "config.h"
*/

#include "log.h"
#include "arg.h"

typedef struct ncotcontext {

  /* ncotconfig *config; */
  ncotarguments *arguments;

  /* global main stuff */ 

  struct ncotnode *globalnodelist;

} ncotcontext;

ncotcontext *ncot_context_new();
void ncot_context_init(ncotcontext *context);
void ncot_context_free(ncotcontext **context);

#endif
