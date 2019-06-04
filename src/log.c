#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include "log.h"

#define DEBUG 0
#include "debug.h"

int ncot_log_level = NCOT_LOG_LEVEL_DEFAULT;

ncot_log_pointer log_ptr = NULL;
const char* logfilename = {"ncot.log"};

void ncot_log_printf( int level, const char *fmt, ... ) {
	NCOT_DEBUG("called log with level: %d, current log_level: %d\n", level, ncot_log_level);
	if ( level <= ncot_log_level ) {
		va_list vl;
		va_start(vl, fmt);
		vprintf(fmt, vl);
		va_end(vl);
	}
}

void ncot_log_logfile( int level, const char *fmt, ... ) {
	int fd, i;
	struct stat logfilestat;
	if ( level <= ncot_log_level ) {
		va_list vl;
		i = stat(logfilename, &logfilestat);
		if (i == 0) {
#ifdef _WIN32
			fd = open(logfilename, O_APPEND|O_WRONLY );
#else
			fd = open(logfilename, O_APPEND|O_SYNC|O_WRONLY );
#endif
		} else {
			fd = creat(logfilename, S_IRWXU);
		}
#ifdef _WIN32
		if (fd > 0) {
			char string[2048];
			int ret;
			va_start(vl, fmt);
			ret = vsprintf((char*)&string, fmt, vl);
			va_end(vl);
			if (ret > 0) write(fd, &string, ret);
			close(fd);
		}
#else
		if (fd > 0) {
			va_start(vl, fmt);
			vdprintf(fd, fmt, vl);
			va_end(vl);
			close(fd);
		}
#endif
	}
}

int
ncot_log_set_logfile(const char *filename) {
	int i;
	int fd;
	struct stat logfilestat;
	/* TODO: need check if filename is a valid filename, alternatively
	 * we could check in arguments parsing */
	i = stat(filename, &logfilestat);
	if (i == 0) {
		unlink(filename);
	}
	if (strlen(filename) != 0) {
		fd = creat(filename, S_IRWXU);
		if (fd < 0) {
			NCOT_LOG_ERROR( "invalid logfilename: %s, %s\n", filename, strerror(errno));
			return -1;
		}
		close(fd);
		logfilename = filename;
		log_ptr = &ncot_log_logfile;
	} else {
		NCOT_LOG_ERROR( "invalid empty logfilename.\n");
		return -1;
	}
	return 0;
}

void ncot_log_init(int level) {
	log_ptr = &ncot_log_printf;
	ncot_log_level = level * 8;

	NCOT_DEBUG("set log level to: %d\n", ncot_log_level);
}

void ncot_log_done() {
}


void ncot_log_hex (char *desc, void *addr, int len) {
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char*)addr;

	// Output description if given.
	if (desc != NULL)
		NCOT_LOG_INFO ("%s:\n", desc);

	if (len == 0) {
		NCOT_LOG_INFO("  ZERO LENGTH\n");
		return;
	}
	if (len < 0) {
		NCOT_LOG_INFO("  NEGATIVE LENGTH: %i\n",len);
		return;
	}

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				NCOT_LOG_INFO ("  %s\n", buff);

			// Output the offset.
			NCOT_LOG_INFO ("  %04x ", i);
		}

		// Now the hex code for the specific character.
		NCOT_LOG_INFO (" %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		NCOT_LOG_INFO ("   ");
		i++;
	}

	// And print the final ASCII bit.
	NCOT_LOG_INFO ("  %s\n", buff);
}
