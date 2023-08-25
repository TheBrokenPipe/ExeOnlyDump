#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include "xodump.h"
#include "helper.h"

/************************* PRIVATE PROCEDURE ******************************
*
* Description
*   Sends CTRL+C to self. Hangs the current thread afterwards.
*
* Arguments
*   None
*
* Returns
*   Nothing
*
* Calls
*   Nothing
*
* Called by
*   prompt_yes_no
*   prompt_ull
*   prompt_str
*
**************************************************************************/
static void ctrl_c(void)
{
	kill(getpid(), SIGINT);
	while (1) {};
}

/************************* PRIVATE PROCEDURE ******************************
*
* Description
*   Changes the text color to blue.
*
* Arguments
*   None
*
* Returns
*   Nothing
*
* Calls
*   Nothing
*
* Called by
*   hex_dump
*
**************************************************************************/
static void blue(void)
{
#if USE_COLOR
	printf("\x1B[1;34m");
	fprintf(stderr, "\x1B[1;34m");
#endif
}

/************************* PRIVATE PROCEDURE ******************************
*
* Description
*   Changes the text color to green.
*
* Arguments
*   None
*
* Returns
*   Nothing
*
* Calls
*   Nothing
*
* Called by
*   hex_dump
*
**************************************************************************/
static void green(void)
{
#if USE_COLOR
	printf("\x1B[1;32m");
	fprintf(stderr, "\x1B[1;32m");
#endif
}

/************************* PRIVATE PROCEDURE ******************************
*
* Description
*   Changes the text color to magenta.
*
* Arguments
*   None
*
* Returns
*   Nothing
*
* Calls
*   Nothing
*
* Called by
*   hex_dump
*
**************************************************************************/
static void magenta(void)
{
#if USE_COLOR
	printf("\x1B[1;35m");
	fprintf(stderr, "\x1B[1;35m");
#endif
}

/************************* PRIVATE PROCEDURE ******************************
*
* Description
*   Changes the text color to red.
*
* Arguments
*   None
*
* Returns
*   Nothing
*
* Calls
*   Nothing
*
* Called by
*   out_error_raw
*
**************************************************************************/
static void red(void)
{
#if USE_COLOR
	printf("\x1B[1;31m");
	fprintf(stderr, "\x1B[1;31m");
#endif
}
/************************* PRIVATE PROCEDURE ******************************
*
* Description
*   Changes the text color to cyan.
*
* Arguments
*   None
*
* Returns
*   Nothing
*
* Calls
*   Nothing
*
* Called by
*   out_text
*
**************************************************************************/
static void cyan(void)
{
#if USE_COLOR
	printf("\x1B[1;36m");
	fprintf(stderr, "\x1B[1;36m");
#endif
}

/************************* PRIVATE PROCEDURE ******************************
*
* Description
*   Changes the text style to bold.
*
* Arguments
*   None
*
* Returns
*   Nothing
*
* Calls
*   Nothing
*
* Called by
*   out_text
*   out_error_raw
*
**************************************************************************/
static void bold(void)
{
#if USE_COLOR
	printf("\x1B[1m");
	fprintf(stderr, "\x1B[1m");
#endif
}

/************************* PRIVATE PROCEDURE ******************************
*
* Description
*   Resets the text color and style.
*
* Arguments
*   None
*
* Returns
*   Nothing
*
* Calls
*   Nothing
*
* Called by
*   hex_dump
*   out_text
*   out_error_raw
*
**************************************************************************/
static void reset(void)	
{
#if USE_COLOR
	printf("\x1B[0m");
	fprintf(stderr, "\x1B[0m");
#endif
}

/************************* PUBLIC PROCEDURE *******************************
*
* Description
*   Outputs a formatted message. Same as printf, except it returns void.
*
* Arguments
*   format  - format string
*   [...]   - elements to format
*
* Returns
*   Nothing
*
* Calls
*   bold
*   cyan
*   reset
*
* Called by
*   prompt_yes_no
*   prompt_ull
*   prompt_str
*   wait_child
*   kill_child
*   auto_dump
*   dbg_map
*   dbg_auto
*   dbg_view
*   dbg_dump
*   dbg_syscall
*   query_break_conds
*   query_mode
*   main
*
**************************************************************************/
void out_text(const char *format, ...)
{
	va_list va;
	bold();
	cyan();
	va_start(va, format);
	vfprintf(stdout, format, va);
	va_end(va);
	reset();
	fflush(stdout);
}

/************************* PUBLIC PROCEDURE *******************************
*
* Description
*   Outputs a formatted error message. Same as printf, except prints to
*   stderr and returns void.
*
* Arguments
*   format  - format string
*   [...]   - elements to format
*
* Returns
*   Nothing
*
* Calls
*   bold
*   red
*   reset
*
* Called by
*   prompt_yes_no
*   prompt_ull
*   prompt_str
*   kill_child
*   dup_file_size
*   break_at_syscall
*   inject_syscall
*   get_mem_map
*   auto_dump
*   dbg_map
*   dbg_auto
*   dbg_view
*   dbg_dump
*   dbg_syscall
*   query_mode
*   main
*
**************************************************************************/
void out_error_raw(const char *format, ...)
{
	va_list va;
	bold();
	red();
	va_start(va, format);
	vfprintf(stderr, format, va);
	va_end(va);
	reset();
	fflush(stderr);
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Reads a line from standard input.
*
* Arguments
*   None
*
* Returns
*   The line entered by the user without line feed, or NULL if EOF is
*   detected.
*
* Calls
*   Nothing
*
* Called by
*   prompt_yes_no
*   prompt_ull
*   prompt_str
*
**************************************************************************/
char *input_line(void)
{
	int c;
	char *result = NULL;
	int i = 0;
	while (1)
	{
		c = fgetc(stdin);
		if (c == EOF || c == '\n')
		{
			break;
		}
		result = (char *)realloc(result, i + 1);
		result[i] = (char)c;
		i++;
	}
	if (c == '\n' || i > 0)
	{
		result = (char *)realloc(result, i + 1);
		result[i] = '\0';
	}
	return result;
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Converts a string to upper case.
*
* Arguments
*   str     - the string to upper case
*
* Returns
*   The upper cased string.
*
* Calls
*   Nothing
*
* Called by
*   prompt_yes_no
*   dbg_view
*   main
*
**************************************************************************/
char *str_to_upper(char *str)
{
	for (char *buff = str; *buff; buff++)
	{
		*buff = toupper(*buff);
	}
	return str;
}

/************************* PUBLIC PROCEDURE *******************************
*
* Description
*   Hex dumps a range of memory. Modified version of
*   https://stackoverflow.com/a/7776146. Assumes that base is a 48-bit
*   pointer.
*
* Arguments
*   ptr     - pointer to the memory to dump
*   size    - the number of bytes to dump
*   base    - base of the hex used for displaying offsets (64-bit number)
*
* Returns
*   Nothing
*
* Calls
*   blue
*   green
*   magenta
*   reset
*
* Called by
*   dbg_view
*
**************************************************************************/
void hex_dump(const void *ptr, size_t size, unsigned long base)
{
	if (ptr && size)
	{
		// Print header.
		blue();
		printf("\nOffset (h)    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  Decoded text\n");
		char text[16 + 1] = { 0 };
		const char *buffer = (const char *)ptr;
		size_t i;
		for (i = 0; i < size; i++)
		{
			if (!(i % 16))
			{
				// Beginning of line.
				if (i)
				{
					// Not first, print prev line's txt.
					magenta();
					printf("  %s\n", text);
					memset(text, 0, sizeof(text));
				}
				// Print address within buffer.
				blue();
				printf("%012lX ", base + (unsigned long)i);
				green();
			}
			// Print each byte's hex value.
			printf(" %02X", (unsigned char)buffer[i]);
			// Cache the text representation to be printed later.
			text[i % 16] = isprint(buffer[i]) ? buffer[i] : '.';
		}
		// Pad to the position of text dump of last line.
		while ((i % 16))
		{
			// Space and 2 hex digits.
			printf("   ");
			i++;
		}
		// Print text of last line.
		magenta();	
		printf("  %s\n", text);	
		reset();
		fflush(stdout);
	}
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Prompts for a yes/no response.
*
* Arguments
*   None
*
* Returns
*   The user response to the prompt.
*
* Calls
*   input_line
*   str_to_upper
*   out_text
*   err_msg
*   ctrl_c
*
* Called by
*   dbg_dump
*   query_break_conds
*   query_mode
*   main
*
**************************************************************************/
bool prompt_yes_no(void)
{
	while (1)
	{
		out_text("> ");
		char *buff = input_line();
		if (buff)
		{
			str_to_upper(buff);
			if (!strcmp(buff, "Y") || !strcmp(buff, "YES"))
			{
				free(buff);
				return true;
			}
			else if (!strcmp(buff, "N") || !strcmp(buff, "NO"))
			{
				free(buff);
				return false;
			}
			free(buff);
			err_msg("Invalid response.\n");
		}
		else
		{
			ctrl_c();
		}
	}
}

/************************* PRIVATE FUNCTION *******************************
*
* Description
*   Checks whether the number in string form is an octal number.
*
* Arguments
*   str     - number in string form
*
* Returns
*   Whether the number is octal.
*
* Calls
*   Nothing
*
* Called by
*   str_to_ull
*
**************************************************************************/
static bool is_num_oct(const char *str)
{
	if (strlen(str) < 3 || str[0] != '0' || str[1] != 'o')
	{
		return false;
	}
	for (size_t i = 2; i < strlen(str); i++)
	{
		if (str[i] < '0' || str[i] > '7')
		{
			return false;
		}
	}
	return true;
}

/************************* PRIVATE FUNCTION *******************************
*
* Description
*   Checks whether the number in string form is a decimal number.
*
* Arguments
*   str     - number in string form
*
* Returns
*   Whether the number is decimal.
*
* Calls
*   Nothing
*
* Called by
*   str_to_ull
*
**************************************************************************/
static bool is_num_dec(const char *str)
{
	size_t start = 0;
	if (strlen(str) > 2 && str[0] == '0' && str[1] == 'd')
	{
		start = 2;
	}
	for (size_t i = start; i < strlen(str); i++)
	{
		if (str[i] < '0' || str[i] > '9')
		{
			return false;
		}
	}
	return true;
}

/************************* PRIVATE FUNCTION *******************************
*
* Description
*   Checks whether the number in string form is a hexadecimal number.
*
* Arguments
*   str     - number in string form
*
* Returns
*   Whether the number is hexadecimal.
*
* Calls
*   Nothing
*
* Called by
*   str_to_ull
*
**************************************************************************/
static bool is_num_hex(const char *str)
{
	if (strlen(str) < 3 || str[0] != '0' || str[1] != 'x')
	{
		return false;
	}
	for (size_t i = 2; i < strlen(str); i++)
	{
		if ((str[i] < '0' || str[i] > '9') && (str[i] < 'A' && str[i] > 'F') && (str[i] < 'a' && str[i] > 'f'))
		{
			return false;
		}
	}
	return true;
}

/************************* PRIVATE FUNCTION *******************************
*
* Description
*   Performs safe and error-checked conversion from string to unsigned
*   long long.
*
* Arguments
*   str     - number in string form
*   base    - the base of the number
*   result  - pointer to store the conversion result
*
* Returns
*   Whether the input is a valid unsigned long long number
*
* Calls
*   Nothing
*
* Called by
*   str_to_ull
*
**************************************************************************/
static bool safe_str_to_ull(const char *str, int base, unsigned long long *result)
{
	if (str && result)
	{
		char *endptr;
		errno = 0;
		*result = strtoull(str, &endptr, base);
		if (!endptr[0] && !errno)
		{
			return true;
		}
	}
	return false;
}
/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Converts a number in string form to an unsigned long long. Supports
*   octal, decimal and hex for string input.
*
* Arguments
*   str     - number in string form
*   result  - pointer to the conversion result
*
* Returns
*   Whether the input is a valid unsigned long long number
*
* Calls
*   is_num_oct
*   is_num_dec
*   is_num_hex
*   safe_str_to_ull
*
* Called by
*   prompt_ull
*
**************************************************************************/
bool str_to_ull(const char *str, unsigned long long *result)
{
	if (str && result)
	{
		const char *numstr;
		int base;
		if (is_num_oct(str))
		{
			numstr = &str[2];
			base = 8;
		}
		else if (is_num_dec(str))
		{
			numstr = (strlen(str) > 2 && str[2] == 'd') ? &str[2] : str;
			base = 10;
		}
		else if (is_num_hex(str))
		{
			numstr = &str[2];
			base = 16;
		}
		else
		{
			return false;
		}
		return safe_str_to_ull(numstr, base, result);
	}
	return false;
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Prompts for a unsigned long long number response.
*
* Arguments
*   None
*
* Returns
*   The user response to the prompt.
*
* Calls
*   input_line
*   str_to_ull
*   out_text
*   err_msg
*
* Called by
*   dbg_view
*   dbg_dump
*   dbg_syscall
*   query_break_conds
*   query_mode
*   main
*
**************************************************************************/
unsigned long long prompt_ull(void)
{
	while (1)
	{
		out_text("> ");
		char *buff = input_line();
		if (buff)
		{
			unsigned long long result;
			if (strlen(buff) && str_to_ull(buff, &result))
			{
				free(buff);
				return result;
			}
			free(buff);
			err_msg("Invalid response.\n");
		}
		else
		{
			ctrl_c();
		}
	}
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Prompts for a string response.
*
* Arguments
*   None
*
* Returns
*   The user response to the prompt.
*
* Calls
*   input_line
*   out_text
*   err_msg
*   ctrl_c
*
* Called by
*   dbg_auto
*   dbg_view
*   dbg_dump
*   query_mode
*   main
*
**************************************************************************/
char *prompt_str(void)
{
	while (1)
	{
		out_text("> ");
		char *buff = input_line();
		if (buff)
		{
			if (strlen(buff))
			{
				return buff;
			}
			free(buff);
			err_msg("Invalid response.\n");
		}
		else
		{
			ctrl_c();
		}
	}
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Waits on a child process.
*
* Arguments
*   pid     - the child's process ID
*
* Returns
*   Whether the wait was successful. Returns false if the child has
*   terminated.
*
* Calls
*   out_text
*
* Called by
*   break_at_syscall
*   inject_syscall
*   main
*
**************************************************************************/
bool wait_child(pid_t pid)
{
	int status;
	if (waitpid(pid, &status, 0) == -1)
	{
		return false;
	}
	if (WIFEXITED(status))
	{
		out_text("Child process %d exited with status %d.\n", pid, WEXITSTATUS(status));
		return false;
	}
	else if (WIFSIGNALED(status))
	{
		out_text("Child process %d was terminated by signal %d.\n", pid, WTERMSIG(status));
		return false;
	}
	return true;
}

/************************* PUBLIC PROCEDURE *******************************
*
* Description
*   Kills the child process.
*
* Arguments
*   pid     - the child's process ID
*
* Returns
*   Nothing
*
* Calls
*   out_text
*   out_error
*
* Called by
*   exit_proc
*
**************************************************************************/
void kill_child(pid_t pid)
{
	// Send kill signal and wait continue child.
	if (kill(pid, SIGKILL) == -1)
	{
		out_error("Failed to kill child process %d (errno = %d).\n", pid, errno);
	}
	
	// Wait for child to quit.
	int status = 0;
	if (waitpid(pid, &status, 0) == -1)
	{
		out_error("Failed to wait for child to exit (errno = %d).\n", errno);
	}
	else
	{
		if (WIFEXITED(status))
		{
			out_text("Child process %d exited with status %d.\n", pid, WEXITSTATUS(status));
		}
		else if (WIFSIGNALED(status))
		{
			out_text("Child process %d was terminated by signal %d.\n", pid, WTERMSIG(status));
		}
		else
		{
			out_text("Child process %d did not terminate.\n", pid);
		}
	}
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Creates the specified file if it doesn't exist.
*
* Arguments
*   filename - name of the specified file
*
* Returns
*   Whether the file has been created, or if it already exists.
*
* Calls
*   Nothing
*
* Called by
*   create_empty_file
*   dbg_dump
*
**************************************************************************/
bool ensure_file_exists(const char *filename)
{
	int errno_bak = errno;
	int fd = open(filename, O_CREAT | O_WRONLY | O_EXCL, S_IRUSR | S_IWUSR);
	if (fd != -1)
	{
		close(fd);
		return true;
	}
	else if (errno = EEXIST)
	{
		errno = errno_bak;
		return true;
	}
	return false;
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Sets the size of the specified file.
*
* Arguments
*   filename - name of the specified file
*   size    - new file size
*
* Returns
*   Whether the file has been successfully resized.
*
* Calls
*   Nothing
*
* Called by
*   create_empty_file
*   auto_dump
*   dbg_dump
*
**************************************************************************/
bool set_file_size(const char *filename, off_t size)
{
	if (truncate(filename, size) == -1)
	{
		return false;
	}
	return true;
}

/************************* PRIVATE FUNCTION *******************************
*
* Description
*   Creates an empty file of a specified size.
*
* Arguments
*   filename - name of the specified file
*   size    - new file size
*
* Returns
*   Whether the file has been successfully created.
*
* Calls
*   Nothing
*
* Called by
*   dup_file_size
*
**************************************************************************/
static bool create_empty_file(const char *filename, off_t size)
{
	int errno_bak = errno;
	unlink(filename);
	errno = errno_bak;
	return ensure_file_exists(filename) && set_file_size(filename, size);
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Gets the size of a file.
*
* Arguments
*   filename - name of the specified file
*   size     - pointer to store the file size
*
* Returns
*   Whether the file size has been successfully obtained.
*
* Calls
*   Nothing
*
* Called by
*   dup_file_size
*   auto_dump
*   dbg_dump
*
**************************************************************************/
bool get_file_size(const char *filename, off_t *size)
{
	struct stat st;
	if (stat(filename, &st) == -1)
	{
		return false;
	}
	*size = st.st_size;
	return true;
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Creates an empty file with the same size as another file.
*
* Arguments
*   outfile - name of the file to create
*   size    - name of the file to get size for outfile
*
* Returns
*   Whether the outfile has been successfully created.
*
* Calls
*   get_file_size
*   create_empty_file
*   out_error
*
* Called by
*   auto_dump
*
**************************************************************************/
bool dup_file_size(const char *outfile, const char *infile)
{
	off_t size;
	if (!get_file_size(infile, &size))
	{
		out_error("Failed to get original executable size (errno = %d).\n", errno);
		return false;
	}
	if (!create_empty_file(outfile, size))
	{
		out_error("Failed to create output file (errno = %d).\n", errno);
		return false;
	}
	return true;
}

/************************* PUBLIC PROCEDURE *******************************
*
* Description
*   Sets the permissions for an executable file. Ignores errors.
*
* Arguments
*   filename - name of the executable to set permissions for
*
* Returns
*   Nothing
*
* Calls
*   Nothing
*
* Called by
*   auto_dump
*
**************************************************************************/
void set_perms(const char *filename)
{
	chmod(filename, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
}
