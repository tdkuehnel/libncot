#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>

#include "log.h"

#define DEBUG 0
#include "debug.h"

int ncot_log_level = NCOT_LOG_LEVEL_DEFAULT;

ncot_log_pointer log_ptr = NULL;
ncot_log_pointer log_buffered_ptr = NULL;
ncot_log_flush_pointer log_buffer_flush_ptr = NULL;

const char* logfilename = {"ncot.log"};

#define NCOT_LOG_BUFFER_LENGTH 2048

char logbuffer[NCOT_LOG_BUFFER_LENGTH];
char *logbufferpointer;
struct timeval stv;
int logtimeofday;
char timestring[256];

void
ncot_log_logfile( int level, const char *fmt, ... )
{
	int fd;
	int i;
	struct stat logfilestat;
	char timestring[256];
	struct timeval tv;
	if ( level <= ncot_log_level ) {
		va_list vl;
		i = stat(logfilename, &logfilestat);
		if (i == 0) {
#ifdef _WIN32
			fd = open(logfilename, O_APPEND|O_WRONLY );
#else
/*			fd = open(logfilename, O_APPEND|O_SYNC|O_WRONLY );*/
			fd = open(logfilename, O_APPEND|O_WRONLY );
 #endif
		} else {
			fd = creat(logfilename, S_IRWXU);
		}
		gettimeofday(&tv, NULL);
		/* This gives bogus usecs for the first timestring
		 * logged after ncot_log_init */
		snprintf (timestring, 256, "[%3ld.%06ld]", tv.tv_sec - stv.tv_sec, tv.tv_usec);
		if (fd > 0) {
#ifdef _WIN32
			char string[2048];
			char *stringptr;
			int ret;
			stringptr = (char*)string;
			switch (level) {
			case NCOT_LOG_LEVEL_ERROR:
				stringptr += sprintf(stringptr, "%s", ANSI_COLOR_RED);
				stringptr += sprintf(stringptr, " Err");
				break;
			case NCOT_LOG_LEVEL_WARNING:
				stringptr += sprintf(stringptr, "%s", ANSI_COLOR_YELLOW);
				stringptr += sprintf(stringptr, "Warn");
				break;
			case NCOT_LOG_LEVEL_INFO:
				stringptr += sprintf(stringptr, "%s", ANSI_COLOR_GREEN);
				stringptr += sprintf(stringptr, "Info");
				break;
			case NCOT_LOG_LEVEL_VERBOSE:
				stringptr += sprintf(stringptr, "%s", ANSI_COLOR_GREEN);
				stringptr += sprintf(stringptr, "Verb");
				break;
			default:
				stringptr += sprintf(stringptr, "%s", ANSI_COLOR_GREEN);
				stringptr += sprintf(stringptr, " Def");
				break;
			}
			stringptr += sprintf(stringptr, "%s", ANSI_COLOR_RESET);
			if (logtimeofday) stringptr += sprintf(stringptr, timestring);
			stringptr += sprintf(stringptr, ": ");
			va_start(vl, fmt);
			ret = vsprintf(stringptr, fmt, vl);
			va_end(vl);
			if (ret > 0) write(fd, &string, ret);
#else
			switch (level) {
			case NCOT_LOG_LEVEL_ERROR:
				dprintf(fd, ANSI_COLOR_RED " Err");
				break;
			case NCOT_LOG_LEVEL_WARNING:
				dprintf(fd, ANSI_COLOR_YELLOW "Warn");
				break;
			case NCOT_LOG_LEVEL_INFO:
				dprintf(fd, ANSI_COLOR_GREEN "Info");
				break;
			case NCOT_LOG_LEVEL_VERBOSE:
				dprintf(fd, ANSI_COLOR_GREEN "Verb");
				break;
			default:
				dprintf(fd, ANSI_COLOR_GREEN " Def");
				break;
			}
			dprintf(fd, ANSI_COLOR_RESET);
			if (logtimeofday) dprintf(fd, timestring);
			dprintf(fd, ": ");
			va_start(vl, fmt);
			vdprintf(fd, fmt, vl);
			va_end(vl);
#endif
			close(fd);
		}
	}
}

void
ncot_log_logfile_buffered( int level, const char *fmt, ... )
{
	int ret;
	int printsize;
	va_list vl;
	return;
	printsize = logbuffer + NCOT_LOG_BUFFER_LENGTH - logbufferpointer;
	va_start(vl, fmt);
	ret = vsnprintf(logbufferpointer, printsize, fmt, vl);
	va_end(vl);
	if (ret >= printsize) {
		ncot_log_logfile_buffer_flush();
		logbufferpointer = logbuffer;
		printsize = logbuffer + NCOT_LOG_BUFFER_LENGTH - logbufferpointer;
		va_start(vl, fmt);
		ret = vsnprintf(logbufferpointer, printsize, fmt, vl);
		va_end(vl);
		if (ret >= printsize) {
			ncot_log_logfile(NCOT_LOG_LEVEL_ERROR, "logbuffer to small for atomic log\n" );
			logbufferpointer = logbuffer;
			return;
		}
	}
	logbufferpointer += ret;
}

void
ncot_log_logfile_buffer_flush()
{
	int fd, i;
	struct stat logfilestat;
	return;
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
	*logbufferpointer = 0;
	if (fd > 0) {
		write(fd, logbuffer, logbufferpointer - logbuffer);
		close(fd);
	}
	logbufferpointer = logbuffer;
}

void
ncot_log_printf( int level, const char *fmt, ... )
{
	/* Set DEBUG 1 and you have an infinite loop :) */
	NCOT_DEBUG("called log with level: %d, current log_level: %d\n", level, ncot_log_level);
	if ( level <= ncot_log_level ) {
		va_list vl;
		va_start(vl, fmt);
		vprintf(fmt, vl);
		va_end(vl);
	}
}

void
ncot_log_printf_buffered( int level, const char *fmt, ... )
{
	if ( level <= ncot_log_level ) {
		va_list vl;
		va_start(vl, fmt);
		vprintf(fmt, vl);
		va_end(vl);
	}
}

void
ncot_log_printf_buffer_flush()
{
}

void
ncot_log_set_loglevel(int loglevel)
{
	ncot_log_level = loglevel;
}

int
ncot_log_set_logfile(const char *filename)
{
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
			NCOT_LOG_ERROR( "ncot_log_set_logfile: invalid logfilename %s, %s\n", filename, strerror(errno));
			return -1;
		}
		close(fd);
		logfilename = filename;
		log_ptr = &ncot_log_logfile;
		log_buffered_ptr = &ncot_log_logfile_buffered;
		log_buffer_flush_ptr = &ncot_log_logfile_buffer_flush;
	} else {
		NCOT_LOG_ERROR( "ncot_log_set_logfile: invalid empty logfilename.\n");
		return -1;
	}
	return 0;
}

void
ncot_log_init(int level) {
	log_ptr = &ncot_log_printf;
	log_buffered_ptr = &ncot_log_printf_buffered;
	log_buffer_flush_ptr = &ncot_log_printf_buffer_flush;
	ncot_log_level = level;
	logbufferpointer = logbuffer;
	logtimeofday = 1;
	gettimeofday(&stv, NULL);
	/* This is a dirty thing of code, but it makes the log time
	 * stamps start at ~ 0.05. */
	while (stv.tv_usec > 50000) gettimeofday(&stv, NULL);
	NCOT_DEBUG("set log level to: %d\n", ncot_log_level);
}

void
ncot_log_done()
{
	NCOT_LOG_INFO_BUFFER_FLUSH();
	log_ptr = NULL;
	log_buffered_ptr = NULL;
	log_buffer_flush_ptr = NULL;
}

void
ncot_log_hex (char *desc, void *addr, int len) {
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char*)addr;

	// Output description if given.
	if (desc != NULL)
		NCOT_LOG_INFO_BUFFERED ("%s:\n", desc);

	if (len == 0) {
		NCOT_LOG_INFO_BUFFERED("  ZERO LENGTH\n");
		return;
	}
	if (len < 0) {
		NCOT_LOG_INFO_BUFFERED("  NEGATIVE LENGTH: %i\n",len);
		return;
	}

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				NCOT_LOG_INFO_BUFFERED ("  %s\n", buff);

			// Output the offset.
			NCOT_LOG_INFO_BUFFERED ("  %04x ", i);
		}

		// Now the hex code for the specific character.
		NCOT_LOG_INFO_BUFFERED (" %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		NCOT_LOG_INFO_BUFFERED ("   ");
		i++;
	}

	// And print the final ASCII bit.
	NCOT_LOG_INFO_BUFFERED ("  %s\n", buff);
	NCOT_LOG_INFO_BUFFER_FLUSH();
}
