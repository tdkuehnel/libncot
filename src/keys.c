#include "autoconfig.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <json-c/json.h>

#include "debug.h"
#include "error.h"
#include "keys.h"
#include "helper.h"

#define NCOT_BUFLEN_KEYFILE 4096

int
ncot_key_is_known(struct ncot_context *context, struct ssh_key_struct *key)
{
	return NCOT_ERROR;
}
