#include "context.h"

nctcontext *nct_context_new() {
  nctcontext *context;
  context = calloc(1, sizeof(nctcontext));
  return context;
}

void nct_context_init(nctcontext *context) {
  if (context) {
    /*    context->config = nct_config_new(); */
    context->arguments = calloc(1, sizeof(nctarguments));    
    context->globalnodelist = NULL;
  } else {
    NCT_LOG_WARNING("Invalid context passed to nct_context_init\n");
  }
}

void nct_context_free(nctcontext **pcontext) {
  nctcontext *context;
  if (pcontext) {
    context = *pcontext;
    if (context) {
      context = *pcontext;
      /*      if (context->config) free(context->config); */
      if (context->arguments) free(context->arguments);
      free(context);
      *pcontext = NULL;
    } else
      NCT_LOG_ERROR("Invalid context\n");
  } else 
    NCT_LOG_ERROR("Invalid argument (*context)\n");
}

