#ifndef NCOT_DEBUG_H
#define NCOT_DEBUG_H

/* simple debug implementation which gets compiled but optimized out if DEBUG not 1
   see http://stackoverflow.com/questions/1644868/c-define-macro-for-debug-printing

   ALLWAYS put a #define DEBUG 0 (or DEBUG_DEEP 0) in front of your #include "debug.h"
   when using the macros or the compiler will complain.

   gcc -DDEBUG ( or -DDEBUG_DEEP ) will be overwritten.
*/

#ifndef DEBUG
#define DEBUG 0
#endif

#include <stdio.h>

#define NCOT_DEBUG(...)							\
	do { if (DEBUG) fprintf(stderr, ## __VA_ARGS__); } while (0)

#define NCOT_NO_DEBUG(...)

#define NCOT_DEBUG_DEEP(...)						\
	do { if (DEBUG_DEEP) fprintf(stderr, ## __VA_ARGS__); } while (0)

#endif
