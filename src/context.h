#ifndef NCT_CONTEXT_H
#define NCT_CONTEXT_H

#include <stdio.h>

struct nctcontext;

/*#include "helper.h"
#include "command.h"
#include "process.h"
#include "pipe.h"
#include "config.h"
*/

#include "log.h"
#include "arg.h"

typedef struct nctcontext {

  /* nctconfig *config; */
  nctarguments *arguments;

  /* global main stuff */ 

  struct nctnode *globalnodelist;

} nctcontext;

nctcontext *nct_context_new();
void nct_context_init(nctcontext *context);
void nct_context_free(nctcontext **context);

#endif
