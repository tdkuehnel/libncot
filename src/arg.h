#ifndef _NCT_ARG_
#define _NCT_ARG_

/* from main config or command line arguments. */
typedef struct nctarguments
{
  char *args[2];                /* arg1 & arg2 */
  int silent, verbose;
  char *config_file;
  char *pidfile_name;
  int log_level;
  int daemonize;
} nctarguments;

void nct_arg_parse(nctarguments *arguments, int argc, char **argv);

#endif
