#include "autoconfig.h"
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "ncot.h"
#include "node.h"

#include "utlist.h"

#include "context.h" 

#define DEBUG 1
#include "debug.h"
#include "log.h"

ncotcontext *context; 
struct ncot_node *node;

int count = 0;
int last_signum = 0;
int r;
char *buf;
int gpid;

void sig_handler(int signum) {
  count++;
  last_signum = signum;
}

struct sigaction new_action, old_action;
/* cpwpipe *tpipe, *ipipe, *inpipe, *outpipe; */

void ncot_client_init(int argc, char **argv) {
  char *str;
  new_action.sa_handler = sig_handler;
  sigemptyset (&new_action.sa_mask);
  new_action.sa_flags = 0;
  sigaction (SIGINT, NULL, &old_action);
  if (old_action.sa_handler != SIG_IGN)
    sigaction (SIGINT, &new_action, NULL);
  sigaction (SIGHUP, NULL, &old_action);
  if (old_action.sa_handler != SIG_IGN)
    sigaction (SIGHUP, &new_action, NULL);
  sigaction (SIGTERM, NULL, &old_action);
  if (old_action.sa_handler != SIG_IGN)
    sigaction (SIGTERM, &new_action, NULL);

  /* command line parsing */
  /* initialize global context */
  context = ncot_context_new();
  ncot_context_init(context);
  
  ncot_arg_parse(context->arguments, argc, argv);
  ncot_log_init(NCOT_LOG_LEVEL_INFO);
  ncot_init();
  NCOT_LOG_INFO("%s %s\n", PACKAGE_STRING, "client");

  node = ncot_node_new();
  if (node) {
    ncot_node_init(node);
    str = NULL;
    uuid_export(node->uuid, UUID_FMT_STR, &str, NULL);
    NCOT_LOG_INFO("Node created with uuid: %s \n", str);

  } else {
    NCOT_LOG_WARNING("unable to create ncot node.");    
  }


  /* main initialization ends here */
}

int main(int argc, char **argv)
{
  int r, highestfd;
  fd_set rfds, wfds;
  sigset_t sigmask;

  ncot_client_init(argc, argv);
  
  /* initialize main loop */
  FD_ZERO(&rfds);
  FD_ZERO(&wfds);

  NCOT_LOG( NCOT_LOG_LEVEL_INFO, "entering main loop, CTRL-C to bail out\n");
 
  while(1) {
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    NCOT_DEBUG("\n");

    /* need to get highest FD number to pass to pselect next */
    r = pselect(highestfd + 1, &rfds, &wfds, NULL, NULL, NULL);

    if (r > 0) { 
      NCOT_DEBUG("input/ouput ready\n");
    } else {
      switch (errno) {
      case EBADF: 
	NCOT_LOG(NCOT_LOG_LEVEL_ERROR, "error during pselect: EBADF\n");
	break;
      case EINTR: 
	NCOT_LOG(NCOT_LOG_LEVEL_INFO, " signal during pselect: EINTR\n");
	break;
      case EINVAL: 
	NCOT_LOG(NCOT_LOG_LEVEL_ERROR, "error during pselect: EINVAL\n");
	break;
      case ENOMEM: 
	NCOT_LOG(NCOT_LOG_LEVEL_ERROR, "error during pselect: ENOMEM\n");
	break;
      default:
	NCOT_LOG(NCOT_LOG_LEVEL_ERROR, "error during pselect: unknown (should never happen)\n");
      }
    }
    if (last_signum != 0) {
      break;
    }
    /*sleep(1);*/
  }
  
  NCOT_LOG(NCOT_LOG_LEVEL_INFO, "%d signals handled\n", count);
  kill(gpid, SIGTERM);

  NCOT_LOG(NCOT_LOG_LEVEL_INFO, "done\n");

  ncot_node_free(&node);

  ncot_log_done();
  ncot_context_free(&context);
  ncot_done();

  return 0;
  
}
