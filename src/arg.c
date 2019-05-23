#include <argp.h>
#include "arg.h"
#include "autoconfig.h"
#include "log.h"

#define DEBUG 0
#define DEBUG_DEEP 0
#include "debug.h"

/* const char *argp_program_version = PACKAGE_STRING; */

const char *argp_program_version = PACKAGE_VERSION;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

/* Program documentation. */
static char doc[] =
	"ncot -- Network of Circle of Trust Client";

/* A description of the arguments we accept. */
static char args_doc[] = "[OPTION...]";

/* The options we understand. */
static struct argp_option options[] = {
	/* long name    sn   arg        flags         description*/
	{"Verbose",     'v', 0,         0,            "Produce verbose output" },
	{"quiet",       'q', 0,         0,            "Don't produce any output" },
	{"silent",      's', 0,         OPTION_ALIAS },
	{"daemonize",   'd', 0,         0,            "Daemonize to background" },
	{"address",     'a', "ADDRESS", 0,            "Address to listen on for control connection" },
	{"port",        'c', "PORT",    0,            "Port to listen on for control connection" },
	{"configfile",  'f', "FILE",    0,            "Use configfile instead of ..." },
	{"logfile",     'g', "FILE",    0,            "Use logfile FILE instead of default ncot.log" },
	{"pidfile",     'p', "PIDFILE", 0,            "Pidfilename to use for this instance" },
	{"loglevel",    'l', "LEVEL",   0,            "Set log level (0 .. 8), default 1" },
	{ 0 }
};

/* Parse a single option. */
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
	/* Get the input argument from argp_parse, which we
	   know is a pointer to our arguments structure. */
	struct ncot_arguments *arguments = state->input;

	switch (key)
	{
	case 'q': case 's':
		arguments->silent = 1;
		break;
	case 'a':
		arguments->address_ip4 = arg;
		break;
	case 'c':
		arguments->port = arg;
		break;
	case 'd':
		arguments->daemonize = 1;
		break;
	case 'g':
		arguments->logfile_name = arg;
		break;
	case 'v':
		arguments->verbose = 1;
		break;
	case 'f':
		arguments->config_file = arg;
		break;
	case 'p':
		arguments->pidfile_name = arg;
		break;
	case 'l':
		arguments->log_level = atoi(arg);
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num >= 2)
			/* Too many arguments. */
			argp_usage (state);

		arguments->args[state->arg_num] = arg;

		break;

	case ARGP_KEY_END:
		if (state->arg_num > 0)
			/* Too many arguments. */
			argp_usage (state);
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

/* Our argp parser. */
static struct argp argp = { options, parse_opt, args_doc, doc };

void ncot_arg_parse(struct ncot_arguments *arguments, int argc, char **argv) {

	/* fill in default values */
	/* FIXME: take ncot.conf path from configure values */
	arguments->config_file = "/etc/ncotd.conf";
	arguments->log_level = NCOT_LOG_LEVEL_DEFAULT;
	arguments->pidfile_name = "ncotd.pid";
	arguments->logfile_name = "ncot.log";
	arguments->address_ip4 = "127.0.0.1";
	arguments->port = "24002";

	NCOT_DEBUG ("OUTPUT_FILE = %s\n"
		"VERBOSE = %s\nSILENT = %s\nLOG_LEVEL = %d\n\n",
		arguments->config_file,
		arguments->verbose ? "yes" : "no",
		arguments->silent ? "yes" : "no",
		arguments->log_level);

	/* FIXME: argp_parse drops out if help/usage is displayed or wrong params provided. Need proper program cleanup. */
	argp_parse (&argp, argc, argv, 0, 0, arguments);

	NCOT_DEBUG ("OUTPUT_FILE = %s\n"
		"VERBOSE = %s\nSILENT = %s\nLOG_LEVEL = %d\n\n",
		arguments->config_file,
		arguments->verbose ? "yes" : "no",
		arguments->silent ? "yes" : "no",
		arguments->log_level);
}
