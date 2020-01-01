#ifndef _NCOT_ARG_
#define _NCOT_ARG_

#include "ssh.h"

/* from main config or command line arguments. */
struct ncot_arguments
{
	char *args[2];                /* arg1 & arg2 */
	int silent, verbose;
	char *config_file;
	char *pidfile_name;
	char *logfile_name;
	char *port;
	char *address_ip4;
	char *ncot_dir;
	char *keypass;
	enum  ncot_ssh_keytype usecipher;
	char *cipherbits;
	int log_level;
	int daemonize;
	int interactive;
	int noautokeygen;
};

int
ncot_arg_parse(struct ncot_arguments *arguments, int argc, char **argv);

#endif
