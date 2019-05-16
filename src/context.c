#include "context.h"

ncotcontext *ncot_context_new() {
  ncotcontext *context;
  context = calloc(1, sizeof(ncotcontext));
  return context;
}

void ncot_context_init(ncotcontext *context) {
  if (context) {
    /*    context->config = ncot_config_new(); */
    context->arguments = calloc(1, sizeof(ncotarguments));    
    context->globalnodelist = NULL;
  } else {
    NCOT_LOG_WARNING("Invalid context passed to ncot_context_init\n");
  }
}

void ncot_context_free(ncotcontext **pcontext) {
  ncotcontext *context;
  if (pcontext) {
    context = *pcontext;
    if (context) {
      context = *pcontext;
      /*      if (context->config) free(context->config); */
      if (context->arguments) free(context->arguments);
      free(context);
      *pcontext = NULL;
    } else
      NCOT_LOG_ERROR("Invalid context\n");
  } else 
    NCOT_LOG_ERROR("Invalid argument (*context)\n");
}

