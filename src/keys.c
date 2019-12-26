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

struct ssh_key_struct*
ncot_node_get_public_key(struct ncot_context *context, struct ncot_node *node)
{
	char *dir;
	int fd;
	char path[NCOT_BUFLEN_KEYFILE] = {0};
	struct json_tokener *tokener;
	enum json_tokener_error jerr;

	dir = ncot_get_user_home_dir();
	if (!dir) dir = "./";
	snprintf(path, sizeof(path), "%s%s", dir, NCOT_PUBLIC_KEYS_FILE);
	fd = open(path, O_RDONLY);
	if (fd <= 0) {
		NCOT_LOG_ERROR("ncot_node_get_public_key: Error opening file %s\n", path);
		return NULL;
	}
	tokener = json_tokener_new();

	return NULL;
}

struct ssh_key_struct*
ncot_node_get_private_key(struct ncot_context *context, struct ncot_node *node)
{
	return NULL;
}

int
ncot_node_save_public_key(struct ncot_context *context, struct ncot_node *node, struct ssh_key_struct *key)
{
	return NCOT_ERROR;
}

int
ncot_node_save_private_key(struct ncot_context *context, struct ncot_node *node, struct ssh_key_struct *key)
{
	return NCOT_ERROR;
}
