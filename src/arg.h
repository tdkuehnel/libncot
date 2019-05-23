#ifndef _NCOT_ARG_
#define _NCOT_ARG_

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
	int log_level;
	int daemonize;
};

void ncot_arg_parse(struct ncot_arguments *arguments, int argc, char **argv);

#endif
