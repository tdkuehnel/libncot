/*#include "argp.h"*/
#include <popt.h>
#include "arg.h"
#include "autoconfig.h"
#include "log.h"

#define DEBUG 0
#define DEBUG_DEEP 0
#include "debug.h"

/* Program documentation. */
static char doc[] =
	"ncot -- Network Circle of Trust Client";

/* A description of the arguments we accept. */
static char args_doc[] = "[OPTION...]";

int
ncot_arg_parse(struct ncot_arguments *arguments, int argc, char **argv) {

	poptContext optCon;   /* context for parsing command-line options */
	char c;
	int i;
	/* FIXME: buffer length ?? */
	char buf[2048];
	struct poptOption optionsTable[] = {
		{ "verbose",    'v', POPT_ARG_NONE,   0,                        0,  "Produce verbose output", NULL },
		{ "quiet",      'q', POPT_ARG_NONE,   0,                        0,  "Don't produce any output", NULL },
#ifndef _WIN32
		{ "daemonize",  'd', POPT_ARG_NONE,   &arguments->daemonize,    0,  "Daemonize to background", NULL },
#endif
		{ "interactive",'i', POPT_ARG_NONE,   &arguments->interactive,  0,  "Enter interactive mode after startup", NULL },
		{ "address",    'a', POPT_ARG_STRING, &arguments->address_ip4,  0,  "Address to listen on for control connection", NULL},
		{ "port",       'c', POPT_ARG_STRING, &arguments->port,         0,  "Port to listen on for control connection", NULL},
		{ "configfile", 'f', POPT_ARG_STRING, &arguments->config_file,  0,  "Use configfile instead of ncot_config.json", NULL},
		{ "logfile",    'g', POPT_ARG_STRING, &arguments->logfile_name, 0,  "Use logfile STRING instead of logging to stdout", NULL},
		{ "pidfile",    'p', POPT_ARG_STRING, &arguments->pidfile_name, 0,  "Pidfilename to use for this instance", NULL},
		{ "loglevel",   'l', POPT_ARG_INT,    &arguments->log_level,    0,  "Set log level (0 .. 8), default 1", NULL},
		POPT_AUTOHELP
		{ NULL, 0, 0, NULL, 0 }
	};

	/* fill in default values */
	/* FIXME: take ncot.conf path from configure values */
	arguments->config_file = "ncot_config.json";
	arguments->log_level = NCOT_LOG_LEVEL_DEFAULT;
	arguments->pidfile_name = "ncotd.pid";
	arguments->logfile_name = "";
	arguments->address_ip4 = "127.0.0.1";
	arguments->port = "24002";
	c = '\0';
	i = 0;

	optCon = poptGetContext(NULL, argc, (const char **)argv, optionsTable, 0);
	poptSetOtherOptionHelp(optCon, args_doc);

/*	if (argc < 1) {
		poptPrintUsage(optCon, stderr, 0);
		exit(1);
	}
*/	/* Now do options processing, get portname */
	while ((c = poptGetNextOpt(optCon)) >= 0) {
		switch (c) {
		case 'a':
			buf[i++] = 'a';
			break;
		case 'c':
			buf[i++] = 'c';
			break;
		case 'd':
			buf[i++] = 'd';
			break;
		case 'f':
			buf[i++] = 'f';
			break;
		case 'g':
			buf[i++] = 'g';
			break;
		case 'l':
			buf[i++] = 'l';
			break;
		case 'p':
			buf[i++] = 'p';
			break;
		case 'q':
			buf[i++] = 'q';
			break;
		case 'v':
			buf[i++] = 'v';
			break;
		}
	}
	if (c < -1) {
		/* an error occurred during option processing */
		fprintf(stderr, "%s: %s\n",
			poptBadOption(optCon, POPT_BADOPTION_NOALIAS),
			poptStrerror(c));
		return 1;
	}
	if (arguments->daemonize && arguments->interactive) {
		fprintf(stderr, "Either daemonizing or interactive mode allowed.\n");
		poptPrintUsage(optCon, stderr, 0);
		return 1;
	}
	poptFreeContext(optCon);

	NCOT_DEBUG ("OUTPUT_FILE = %s\n"
		"VERBOSE = %s\nSILENT = %s\nLOG_LEVEL = %d LOG_FILE = %s\n\n",
		arguments->config_file,
		arguments->verbose ? "yes" : "no",
		arguments->silent ? "yes" : "no",
		arguments->log_level,
		arguments->logfile_name);

	return 0;
}
