#include "context.h"

struct ncot_context*
ncot_context_new() {
	struct ncot_context *context;
	context = calloc(1, sizeof(struct ncot_context));
	return context;
}

void ncot_context_init(struct ncot_context *context) {
	if (context) {
		/*    context->config = ncot_config_new(); */
		context->arguments = calloc(1, sizeof(struct ncot_arguments));
		context->globalnodelist = NULL;
		context->controlconnection = ncot_connection_new();
		ncot_connection_init(context->controlconnection, NCOT_CONN_CONTROL);
	} else {
		NCOT_LOG_WARNING("Invalid context passed to ncot_context_init\n");
	}
}

void ncot_context_free(struct ncot_context **pcontext) {
	struct ncot_context *context;
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

