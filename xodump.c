                    /* ExeOnlyDump */
/* Copyright (c) 2023 Broken Pipe. All rights reserved. */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include "xodump.h"
#include "helper.h"
#include "inject.h"

// A program I wrote while taking a C programming course in university
// to dump the execute-only binaries of assignment solutions the
// professors put up for students to test their code against.

// Works for both statically- and dynamically-linked, normal and SUID
// Linux binaries.

/* DEBUGGER - MEMORY VIEW TYPE */
typedef enum
{
	NONE,
	HEX,
	INT,
	STR
} VIEW_TYPE;

/* DUMPER - OPERATION MODE */
typedef enum
{
	UNKNOWN,
	UNATTENDED,
	AUTOMATIC,
	INTERACTIVE,
	QUIT
} MODE;

/* GLOBAL VARIABLES */
int rwpipe[2]; // Pipe for communication between parent and child.

pid_t child_pid = -1; // Child process PID.

char *auto_outfile; // Auto-dump output file.

/************************* PRIVATE PROCEDURE ******************************
*
* Description
*   Exit hook to perform clean-up.
*
* Arguments
*   None
*
* Returns
*   Nothing
*
* Calls
*   kill_child
*
* Called by
*   [CRT]
*
**************************************************************************/
static void exit_proc(void)
{
	if (rwpipe[0])
	{
		close(rwpipe[0]);
	}
	if (rwpipe[1])
	{
		close(rwpipe[1]);
	}
	if (child_pid != -1 && !kill(child_pid, 0))
	{
		kill_child(child_pid);
	}
	if (auto_outfile)
	{
		free(auto_outfile);
	}
}

/************************* PRIVATE FUNCTION *******************************
*
* Description
*   Gets the memory map (/proc/self/maps) for the child process. Only
*   reads the first MAP_SIZE bytes of that file.
*
* Arguments
*   pid     - the child's process ID
*   fds     - file descriptors of a pipe between the parent and the child
*
* Returns
*   Contents of the child's /proc/self/maps file.
*
* Calls
*   child_open
*   child_read
*   inject_close
*   out_error
*
* Called by
*   auto_dump
*   dbg_map
*
**************************************************************************/
static char *get_mem_map(pid_t pid, int *fds)
{
	int fd_map = child_open(pid, fds, "/proc/self/maps", O_RDONLY, 0);
	if (fd_map != -1)
	{
		char *mapbuf = (char *)malloc(MAP_SIZE);
		ssize_t bytesrd = child_read(pid, fds, fd_map, mapbuf, MAP_SIZE);
		inject_close(pid, fd_map);
		if (bytesrd == -1)
		{
			free(mapbuf);
			out_error("Failed to read \"/proc/self/maps\".\n");
			return NULL;
		}
		else
		{
			mapbuf = (char *)realloc(mapbuf, bytesrd + 1);
			mapbuf[bytesrd] = '\0';
			return mapbuf;
		}
	}
	else
	{
		out_error("Failed to open \"/proc/self/maps\" (errno = %d).\n", errno);
		return NULL;
	}
}

/************************* PRIVATE FUNCTION *******************************
*
* Description
*   Automatically dumps the child process' main executable.
*
* Arguments
*   pid     - the child's process ID
*   fds     - file descriptors of a pipe between the parent and the child
*   outfile - path to the output file
*
* Returns
*   Whether the auto dump was successful.
*
* Calls
*   get_mem_map
*   child_readlink
*   dup_file_size
*   child_open
*   inject_lseek
*   inject_write
*   inject_close
*   get_file_size
*   set_file_size
*   out_text
*   out_error
*
* Called by
*   dbg_auto
*   main
*
**************************************************************************/
static bool auto_dump(pid_t pid, int *fds, const char *outfile)
{
	bool result = false;

	// Get the memory map of the child process.
	char *memmap = get_mem_map(pid, fds);
	if (memmap)
	{
		// Get the path to the execute-only executable.
		char *selfpath = (char *)malloc(4096);
		if (child_readlink(pid, fds, "/proc/self/exe", selfpath, 4096) != -1)
		{
			// Create the output file.
			if (dup_file_size(outfile, selfpath))
			{
				// Open output file and dump executable.
				int outfd = child_open(pid, fds, outfile, O_WRONLY, 00777);
				if (outfd != -1)
				{
					// Find segments from the executable we'd like to dump, then dump them.
					int n;
					char *start, *end;
					off_t offset;
					char *segpath = (char *)malloc(4096);
					FILE *fpmap = fmemopen(memmap, strlen(memmap), "r");
					out_text("\n");
					while((n = fscanf(fpmap, "%p-%p%*s%lx%*s%*s%*[ ]%[^\n ]\n", (void **)&start, (void **)&end, (long unsigned int *)&offset, segpath)) != EOF)
					{
						if (n == 4 && !strcmp(segpath, selfpath))
						{
							out_text("Dumping %p - %p to \"%s\" (\"%s\" offset %#lx)...\n", (void *)start, (void *)end, outfile, segpath, offset);
							inject_lseek(pid, outfd, offset, SEEK_SET);
							inject_write(pid, outfd, start, (size_t)(end - start));
						}
					}
					fclose(fpmap);
					inject_close(pid, outfd);

					// Correct size if we have dumped beyond the end of the executable.
					off_t origsize = 0;
					off_t currentsize = 0;
					get_file_size(selfpath, &origsize);
					get_file_size(outfile, &currentsize);
					if (currentsize > origsize && set_file_size(outfile, origsize))
					{
						out_text("Removed %ld bytes of over-dumped data.\n", currentsize - origsize);
					}

					// Set permissions for output file (rwxr-xr-x).
					set_perms(outfile);
					out_text("\n");
					result = true;
				}
				else
				{
					out_error("Failed to open the file \"%s\" for child process (errno = %d).\n", outfile, errno);
				}
			}
			else
			{
				out_error("Failed to create output file.\n");
			}
		}
		else
		{
			out_error("Failed to get path to executable.\n");
		}
		free(selfpath);
		free(memmap);
	}
	else
	{
		out_error("Failed to get memory map of child process.\n");
	}
	return result;
}

/************************* PRIVATE PROCEDURE ******************************
*
* Description
*   Prints the memory map of the child process.
*
* Arguments
*   pid     - the child's process ID
*   fds     - file descriptors of a pipe between the parent and the child
*
* Returns
*   Nothing
*
* Calls
*   get_mem_map
*   out_text
*   out_error
*
* Called by
*   main
*
**************************************************************************/
static void dbg_map(pid_t pid, int *fds)
{
	char *maps = get_mem_map(pid, fds);
	if (!maps)
	{
		out_error("Failed to get memory map of child process.\n");
	}
	else
	{
		out_text("Memory map of process %d:\n\n%s", pid, maps);
		free(maps);
	}
}

/************************* PRIVATE PROCEDURE ******************************
*
* Description
*   Prints the memory map of the child process.
*
* Arguments
*   pid     - the child's process ID
*   fds     - file descriptors of a pipe between the parent and the child
*
* Returns
*   Nothing
*
* Calls
*   prompt_str
*   auto_dump
*   out_text
*   out_error
*
* Called by
*   main
*
**************************************************************************/
static void dbg_auto(pid_t pid, int *fds)
{
	out_text("AUTO allows you to auto-dump the running executable to a disk file.\n\nOutput file:\n");
	char *output = prompt_str();
	if (!auto_dump(pid, fds, output))
	{
		out_error("Failed to auto-dump child process.\n");
	}
	else
	{
		out_text("Executable successfully auto-dumped to \"%s\".\n", output);
	}
	free(output);
}

/************************* PRIVATE PROCEDURE ******************************
*
* Description
*   Displays a region of memory.
*
* Arguments
*   pid     - the child's process ID
*   fds     - file descriptors of a pipe between the parent and the child
*
* Returns
*   Nothing
*
* Calls
*   prompt_ull
*   prompt_str
*   str_to_upper
*   child_to_parent
*   hex_dump
*   err_msg
*   out_text
*   out_error
*
* Called by
*   main
*
**************************************************************************/
static void dbg_view(pid_t pid, int *fds)
{
	out_text("VIEW allows you to view a region of the child's memory.\n\nAddress:\n");
	void *ptr = (void *)prompt_ull();
	out_text("\nType (H[ex]/I[nt]/S[tr]):\n");
	char *type = str_to_upper(prompt_str());
	VIEW_TYPE vtype = NONE;
	if (!strcmp(type, "H") || !strcmp(type, "HEX"))
	{
		vtype = HEX;
	}
	if (!strcmp(type, "I") || !strcmp(type, "INT"))
	{
		vtype = INT;
	}
	if (!strcmp(type, "S") || !strcmp(type, "STR"))
	{
		vtype = STR;
	}
	free(type);
	char *str;
	switch (vtype)
	{
		case HEX:
			out_text("\nLength to hex-dump:\n");
			size_t length = (size_t)prompt_ull();
			void *buff = malloc(length);
			ssize_t bytesrd = child_to_parent(pid, fds, ptr, buff, length);
			if (bytesrd == -1)
			{
				out_error("Failed to read memory.\n");
				free(buff);
				return;
			}
			hex_dump(buff, (size_t)bytesrd, (uint64_t)ptr);
			free(buff);
			break;
		case INT:
			out_text("\nType of integer ((U)Int8/(U)Int16/(U)Int32/(U)Int64):\n");
			char *inttype = str_to_upper(prompt_str());
			if (!strcmp(inttype, "UINT8"))
			{
				uint8_t num;
				if (child_to_parent(pid, fds, ptr, &num, sizeof(num)) == sizeof(num))
				{
					out_text("  %lu | 0x%lx\n", (unsigned long)num, (unsigned long)num);
				}
				else
				{
					out_error("Failed to read UInt8.\n");
				}
			}
			else if (!strcmp(inttype, "INT8"))
			{
				int8_t num;
				if (child_to_parent(pid, fds, ptr, &num, sizeof(num)) == sizeof(num))
				{
					out_text("  %ld | 0x%lx\n", (long)num, (long)num);
				}
				else
				{
					out_error("Failed to read Int8.\n");
				}
			}
			else if (!strcmp(inttype, "UINT16"))
			{
				uint16_t num;
				if (child_to_parent(pid, fds, ptr, &num, sizeof(num)) == sizeof(num))
				{
					out_text("  %lu | 0x%lx\n", (unsigned long)num, (unsigned long)num);
				}
				else
				{
					out_error("Failed to read UInt16.\n");
				}
			}
			else if (!strcmp(inttype, "INT16"))
			{
				int16_t num;
				if (child_to_parent(pid, fds, ptr, &num, sizeof(num)) == sizeof(num))
				{
					out_text("  %ld | 0x%lx\n", (long)num, (long)num);
				}
				else
				{
					out_error("Failed to read Int16.\n");
				}
			}
			else if (!strcmp(inttype, "UINT32"))
			{
				uint32_t num;
				if (child_to_parent(pid, fds, ptr, &num, sizeof(num)) == sizeof(num))
				{
					out_text("  %lu | 0x%lx\n", (unsigned long)num, (unsigned long)num);
				}
				else
				{
					out_error("Failed to read UInt32.\n");
				}
			}
			else if (!strcmp(inttype, "INT32"))
			{
				int32_t num;
				if (child_to_parent(pid, fds, ptr, &num, sizeof(num)) == sizeof(num))
				{
					out_text("  %ld | 0x%lx\n", (long)num, (long)num);
				}
				else
				{
					out_error("Failed to read Int32.\n");
				}
			}
			else if (!strcmp(inttype, "UINT64"))
			{
				uint64_t num;
				if (child_to_parent(pid, fds, ptr, &num, sizeof(num)) == sizeof(num))
				{
					out_text("  %lu | 0x%lx\n", (unsigned long)num, (unsigned long)num);
				}
				else
				{
					out_error("Failed to read UInt64.\n");
				}
			}
			else if (!strcmp(inttype, "INT64"))
			{
				int64_t num;
				if (child_to_parent(pid, fds, ptr, &num, sizeof(num)) == sizeof(num))
				{
					out_text("  %ld | 0x%lx\n", (long)num, (long)num);
				}
				else
				{
					out_error("Failed to read Int64.\n");
				}
			}
			else
			{
				err_msg("Invalid integer type.\n");
			}
			free(inttype);
			break;
		case STR:
			str = (char *)malloc(sizeof(char));
			str[0] = '\0';
			bool err = false;
			while (1)
			{
				size_t len = strlen(str);
				if (child_to_parent(pid, fds, (char *)ptr + len, &str[len], sizeof(char)) != sizeof(char))
				{
					str[len] = '\0';
					err = true;
				}
				if (!str[len])
				{
					break;
				}
				str = (char *)realloc(str, len + 2);
				str[len + 1] = '\0';
			}
			if (err && !strlen(str))
			{
				out_error("Failed to read string.");
			}
			else
			{
				if (err)
				{
					out_text("  \"%s[READ_ERROR]\"\n", str);
				}
				else
				{
					out_text("  \"%s\"\n", str);
				}
			}
			free(str);
			break;
		default:
			err_msg("Invalid display type.\n");
			break;
	}
}

/************************* PRIVATE PROCEDURE ******************************
*
* Description
*   Dumps a region of memory to a disk file.
*
* Arguments
*   pid     - the child's process ID
*   fds     - file descriptors of a pipe between the parent and the child
*
* Returns
*   Nothing
*
* Calls
*   prompt_yes_no
*   prompt_ull
*   prompt_str
*   child_to_parent
*   ensure_file_exists
*   get_file_size
*   set_file_size
*   out_text
*   out_error
*
* Called by
*   main
*
**************************************************************************/
static void dbg_dump(pid_t pid, int *fds)
{
	out_text("DUMP allows you to dump a memory range to a disk file.\n\nStart address:\n");
	void *start = (void *)prompt_ull();
	out_text("\nLength to dump:\n");
	size_t length = (size_t)prompt_ull();
	out_text("\nOutput file name:\n");
	char *output = prompt_str();
	out_text("\nOutput file offset:\n");
	off_t offset = (off_t)prompt_ull();
	out_text("\nBegin dumping? [Y/N]\n");
	if (prompt_yes_no())
	{
		void *buff = malloc(length);
		if (child_to_parent(pid, fds, start, buff, length) != -1)
		{
			off_t size;
			off_t min_size = offset + length;
			if (ensure_file_exists(output) && get_file_size(output, &size) && set_file_size(output, (size > min_size) ? size : min_size))
			{
				int fd = open(output, O_WRONLY);
				if (fd != -1)
				{
					if (lseek(fd, offset, SEEK_SET) != -1)
					{
						ssize_t written = write(fd, buff, length);
						out_text("%d bytes written.\n", (int)written);
					}
					else
					{
						out_error("Failed to seek output file to %#lx.\n", (unsigned long)offset);
					}
					close(fd);
				}
				else
				{
					out_error("Failed to open output file.\n");
				}
			}
			else
			{
				out_error("Failed to prepare output file.\n");
			}
		}
		else
		{
			out_error("Failed to read process memory.\n");
		}
		free(buff);
	}
	free(output);
}

/************************* PRIVATE PROCEDURE ******************************
*
* Description
*   Injects a syscall.
*
* Arguments
*   pid     - the child's process ID
*   fds     - file descriptors of a pipe between the parent and the child
*
* Returns
*   Nothing
*
* Calls
*   prompt_ull
*   inject_syscall
*   out_text
*   out_error
*
* Called by
*   main
*
**************************************************************************/
static void dbg_syscall(pid_t pid, int *fds)
{
	(void)fds;
	out_text("SYSCALL allows you to execute a syscall on behalf of the child process.\n\nSyscall number:\n");
	unsigned long rax = prompt_ull();
	out_text("RDI:\n");
	unsigned long rdi = prompt_ull();
	out_text("RSI:\n");
	unsigned long rsi = prompt_ull();
	out_text("RDX:\n");
	unsigned long rdx = prompt_ull();
	out_text("R10:\n");
	unsigned long r10 = prompt_ull();
	out_text("R8:\n");
	unsigned long r8 = prompt_ull();
	out_text("R9:\n");
	unsigned long r9 = prompt_ull();
	unsigned long result;
	if (!inject_syscall(pid, rax, rdi, rsi, rdx, r10, r8, r9, &result))
	{
		out_error("Failed to inject syscall.\n");
		return;
	}
	int syserr = 0;
	long retval = 0;
	if (result > -4096ULL)
	{
		syserr = -(int)result;
		retval = -1;
	}
	else
	{
		retval = (long)result;
	}
	out_text("Result: RAX = %#lx (return value = %ld, errno = %d).\n", result, retval, syserr);
}

/************************* PRIVATE FUNCTION *******************************
*
* Description
*   Queries the user for break conditions.
*
* Arguments
*   None
*
* Returns
*   The break conditions specified by the user.
*
* Calls
*   prompt_yes_no
*   prompt_ull
*   out_text
*
* Called by
*   main
*
**************************************************************************/
static brkcond_t query_break_conds(void)
{
	brkcond_t conditions = {0};
	out_text("\nConditions? [Y/N]\n");
	if (prompt_yes_no())
	{
		out_text("Conditional RDI? [Y/N]\n");
		conditions.chkrdi = prompt_yes_no();
		if (conditions.chkrdi)
		{
			out_text("Desired RDI value:\n");
			conditions.rdi = prompt_ull();
		}
		out_text("Conditional RSI? [Y/N]\n");
		conditions.chkrsi = prompt_yes_no();
		if (conditions.chkrsi)
		{
			out_text("Desired RSI value:\n");
			conditions.rsi = prompt_ull();
		}
		out_text("Conditional RDX? [Y/N]\n");
		conditions.chkrdx = prompt_yes_no();
		if (conditions.chkrdx)
		{
			out_text("Desired RDX value:\n");
			conditions.rdx = prompt_ull();
		}
		out_text("Conditional R10? [Y/N]\n");
		conditions.chkr10 = prompt_yes_no();
		if (conditions.chkr10)
		{
			out_text("Desired R10 value:\n");
			conditions.r10 = prompt_ull();
		}
		out_text("Conditional R8? [Y/N]\n");
		conditions.chkr8 = prompt_yes_no();
		if (conditions.chkr8)
		{
			out_text("Desired R8 value:\n");
			conditions.r8 = prompt_ull();
		}
		out_text("Conditional R9? [Y/N]\n");
		conditions.chkr9 = prompt_yes_no();
		if (conditions.chkr9)
		{
			out_text("Desired R9 value:\n");
			conditions.r9 = prompt_ull();
		}
	}
	return conditions;
}

/************************* PRIVATE FUNCTION *******************************
*
* Description
*   Queries the user for operation mode.
*
* Arguments
*   None
*
* Returns
*   The operation mode specified by the user.
*
* Calls
*   prompt_yes_no
*   prompt_ull
*   out_text
*   err_msg
*
* Called by
*   main
*
**************************************************************************/
static MODE query_mode(void)
{
	if (auto_outfile)
	{
		return UNATTENDED;
	}

	// Show warning.
	out_text("\nAdministrators may know that you're trying to dump execute-only executables, continue? [Y/N]\n");
	if (!prompt_yes_no())
	{
		return QUIT;
	}

	// Mode selection.
	out_text("\nMode selection:\n    [1] Automatic\n    [2] Interactive\n    [3] Quit\n");
	while (1)
	{
		switch ((int)prompt_ull())
		{
			case 1:
				out_text("\nOutput file:\n");
				auto_outfile = prompt_str();
				return AUTOMATIC;
			case 2:
				return INTERACTIVE;
			case 3:
				return QUIT;
			default:
				err_msg("Invalid mode selection.\n");
				break;
		}
	}
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   The main function - program entry point.
*
* Arguments
*   argc    - argument count
*   argv    - argument vector
*
* Returns
*   Exit status of the application.
*
* Calls
*   query_mode
*   wait_child
*   query_break_conds
*   break_at_syscall
*   str_to_upper
*   dbg_dump
*   dbg_map
*   dbg_auto
*   dbg_view
*   dbg_syscall
*   prompt_yes_no
*   out_text
*   out_error
*   err_msg
*
* Called by
*   [CRT]
*
**************************************************************************/
int main(int argc, char **argv)
{
	if (argc < 2)
	{
		out_text("xodump [-o outfile] <executable> [args]\n");
		return 1;
	}

	char *toexe = argv[1];
	char **args = &argv[1];

	if (!strcmp(argv[1], "-o"))
	{
		if (argc >= 4)
		{
			auto_outfile = strdup(argv[2]);
			toexe = argv[3];
			args = &argv[3];
		}
		else
		{
			err_msg("Too few arguments.\n");
			return -1;
		}
	}

	atexit(exit_proc);

	out_text("ExeOnlyDump 1.00 - Linux Execute-Only Executable Dumper\n"
	"(c) 2023 Broken Pipe. All rights reserved.\n"
	"Note: For research and learning purposes only.\n");

	// Get operation mode.
	MODE mode = query_mode();
	if (mode == QUIT)
	{
		return 0;
	}

	// Create communication pipe.
	if (pipe(rwpipe) == -1)
	{
		out_error("Failed to create pipe (errno = %d).\n", errno);
		return -1;
	}

	// Fork the process.
	child_pid = fork();
	if (child_pid == -1)
	{
		out_error("Failed to fork (errno = %d).\n", errno);
		return -1;
	}

	// Child and parent logic.
	if (!child_pid)
	{
		// Child.
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
		{
			out_error("Failed to PTRACE child process (errno = %d).\n", errno);
			return -1;
		}
		execvp(toexe, args);
		out_error("Failed to execute the executable \"%s\" (errno = %d)\n", toexe, errno);
		return -1;
	}
	else
	{
		// Parent.
		// Wait for child to become ready.
		if (!wait_child(child_pid))
		{
			out_error("Failed to wait for child to halt (errno = %d).\n", errno);
			return -1;
		}

		out_text("\n\"%s\" is running with process id %d.\n", toexe, child_pid);

		// Break at first syscall.
		if (ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL) == -1)
		{
			out_error("Failed to break at first syscall (errno = %d).\n", errno);
			return -1;
		}
		if (!wait_child(child_pid))
		{
			out_error("Failed to wait for child to break at first syscall (errno = %d).\n", errno);
			return -1;
		}

		// If this is an unknown executable, we want to have it dumped before getting to main(),
		// and then terminate the child, this way it won't mess with the global variables and it
		// won't be able to perform any form of logging.

		if (mode == INTERACTIVE)
		{
			// System call 12 is brk, which is almost always the syscall after execve.
			out_text("\nWhich syscall would you like to break at? Please enter a number (default is 12).\n");
			long tobreak = (long)prompt_ull();
			brkcond_t conditions = query_break_conds();
			// Break at the breakpoint.
			if (!break_at_syscall(tobreak, child_pid, conditions))
			{
				out_error("Failed to break at desired syscall.\n", errno);
				return -1;
			}

			// Interactive mode.
			dbg_map(child_pid, rwpipe);
			while (1)
			{
				out_text("\nEnter a command: [DUMP/VIEW/MAP/AUTO/SYSCALL/QUIT/GO/SYS]\n");
				char *input = str_to_upper(prompt_str());
				if (!strcmp(input, "DUMP"))
				{
					dbg_dump(child_pid, rwpipe);
				}
				else if (!strcmp(input, "MAP") || !strcmp(input, "M"))
				{
					dbg_map(child_pid, rwpipe);
				}
				else if (!strcmp(input, "AUTO") || !strcmp(input, "A"))
				{
					dbg_auto(child_pid, rwpipe);
				}
				else if (!strcmp(input, "VIEW") || !strcmp(input, "D") || !strcmp(input, "V"))
				{
					dbg_view(child_pid, rwpipe);
				}
				else if (!strcmp(input, "SYSCALL"))
				{
					dbg_syscall(child_pid, rwpipe);
				}
				else if (!strcmp(input, "SYS"))
				{
					out_text("Enter system command:\n");
					system(prompt_str());
				}
				else if (!strcmp(input, "QUIT") || !strcmp(input, "Q") || !strcmp(input, "E"))
				{
					free(input);
					return 0;
				}
				else if (!strcmp(input, "GO") || !strcmp(input, "G"))
				{
					free(input);
					break;
				}
			}
		}
		else
		{
			// Auto mode.
			if (!auto_dump(child_pid, rwpipe, auto_outfile))
			{
				out_error("Executable auto-dump failed.\n");
				return -1;
			}
			out_text("Executable successfully auto-dumped to \"%s\".\n", auto_outfile);
			// Quit (which kills child) if we're in unattended mode.
			if (mode == UNATTENDED)
			{
				return 0;
			}
			// Prompt for continue if in auto or interactive mode.
			out_text("\nWould you like to continue the child process? [Y/N]\n");
			if (!prompt_yes_no())
			{
				return 0;
			}
		}

		// Continue running our child.
		if (ptrace(PTRACE_CONT, child_pid, NULL, NULL) == -1)
		{
			out_error("Failed to continue the child process (errno = %d).\n", errno);
			return -1;
		}

		// Wait for child to quit.
		wait_child(child_pid);
	}
	return 0;
}
