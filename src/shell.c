#include <stdio.h>
#include <stdlib.h>

#include "error.h"

#define NCOT_READLINE_BUFSIZE 1024

char *ncot_read_line(void)
{
	int bufsize = NCOT_READLINE_BUFSIZE;
	int position = 0;
	char *buffer;
	int c;

	buffer = malloc(sizeof(char) * bufsize);
	RETURN_NULL_IF_NULL(buffer, "ncot_read_line: out of mem\n");

	while (1) {
		// Read a character
		c = getchar();

		// If we hit EOF, replace it with a null character and return.
		if (c == EOF || c == '\n') {
			buffer[position] = '\0';
			return buffer;
		} else {
			buffer[position] = c;
		}
		position++;

		// If we have exceeded the buffer, reallocate.
		if (position >= bufsize) {
			bufsize += NCOT_READLINE_BUFSIZE;
			buffer = realloc(buffer, bufsize);
			RETURN_NULL_IF_NULL(buffer, "ncot_read_line: out of mem\n");
		}
	}
}
