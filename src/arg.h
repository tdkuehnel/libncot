#ifndef _NCOT_ARG_
#define _NCOT_ARG_

/* from main config or command line arguments. */
typedef struct ncotarguments
{
  char *args[2];                /* arg1 & arg2 */
  int silent, verbose;
  char *config_file;
  char *pidfile_name;
  int log_level;
  int daemonize;
} ncotarguments;

void ncot_arg_parse(ncotarguments *arguments, int argc, char **argv);

#endif
