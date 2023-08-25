#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include "xodump.h"
#include "helper.h"
#include "inject.h"

/************************* PRIVATE FUNCTION *******************************
*
* Description
*   Checks if the current register set matches the conditions specified.
*
* Arguments
*   conditions - the conditions to check
*   regs    - the registers
*
* Returns
*   Whether the conditions are met.
*
* Calls
*   Nothing
*
* Called by
*   break_at_syscall
*
**************************************************************************/
static bool check_conditions(brkcond_t conditions, struct user_regs_struct regs)
{
	if (conditions.chkrdi && regs.rdi != conditions.rdi)
	{
		return false;
	}
	if (conditions.chkrsi && regs.rsi != conditions.rsi)
	{
		return false;
	}
	if (conditions.chkrdx && regs.rdx != conditions.rdx)
	{
		return false;
	}
	if (conditions.chkr10 && regs.r10 != conditions.r10)
	{
		return false;
	}
	if (conditions.chkr8 && regs.r8 != conditions.r8)
	{
		return false;
	}
	if (conditions.chkr8 && regs.r9 != conditions.r9)
	{
		return false;
	}
	return true;
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Breaks at the entry to the desired syscall. It is assumed that the
*   program is stopped before or at the entry of a syscall when this
*   function is called.
*
* Arguments
*   id      - the syscall number to break at
*   pid     - the child's process ID
*   conditions - the syscall conditions
*
* Returns
*   Whether the break was successful. Returns false if the child has
*   terminated.
*
* Calls
*   check_conditions
*   wait_child
*   out_error
*
* Called by
*   main
*
**************************************************************************/
bool break_at_syscall(long id, pid_t pid, brkcond_t conditions)
{
	while (1)
	{
		struct user_regs_struct regs;
		if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
		{
			out_error("PTRACE_GETREGS failed (errno = %d).\n", errno);
			return false;
		}
		if ((long)regs.orig_rax == id && check_conditions(conditions, regs))
		{
			break; // Now stopped at the desired syscall, return control to the parent function.
		}

		// We're at a syscall entry (not the one we want to break at), execute the syscall and wait for it to finish.
		if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1)
		{
			out_error("PTRACE_SYSCALL failed (errno = %d).\n", errno);
			return false;
		}
		if (!wait_child(pid))
		{
			out_error("Failed to wait for syscall to finish (errno = %d).\n", errno);
			return false;
		}
		// Break at next syscall entry.
		if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1)
		{
			out_error("PTRACE_SYSCALL failed (errno = %d).\n", errno);
			return false;
		}
		if (!wait_child(pid))
		{
			out_error("Failed to wait for the next syscall (errno = %d).\n", errno);
			return false;
		}
	}
	return true;
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Injects a syscall execution. It is assumed that the program is stopped
*   at the entry of a syscall when this function is called. The state of
*   the child program will not be changed (eg: instruction pointer will
*   still be the same after the injected syscall).
*
* Arguments
*   pid     - the child's process ID
*   rax     - rax register for syscall
*   rdi     - rax register for syscall
*   rsi     - rax register for syscall
*   rdx     - rax register for syscall
*   r10     - rax register for syscall
*   r8      - rax register for syscall
*   r9      - rax register for syscall
*   result  - pointer to store the result of the injected syscall
*
* Returns
*   Whether the syscall injection was successful. Returns false if the
*   child has terminated.
*
* Calls
*   wait_child
*   out_error
*
* Called by
*   dbg_syscall
*   inject_read
*   inject_write
*   inject_open
*   inject_close
*   inject_lseek
*   inject_mmap
*   inject_munmap
*   inject_readlink
*
**************************************************************************/
bool inject_syscall(pid_t pid,
		unsigned long rax,
		unsigned long rdi,
		unsigned long rsi,
		unsigned long rdx,
		unsigned long r10,
		unsigned long r8,
		unsigned long r9,
		unsigned long *result)
{
	// Get original registers.
	struct user_regs_struct orig_regs;
	if (ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs) == -1)
	{
		out_error("Pre-syscall PTRACE_GETREGS failed (errno = %d).\n", errno);
		return false;
	}

	// Create manipulated register set.
	struct user_regs_struct temp_regs = orig_regs;
	temp_regs.orig_rax = rax;
	temp_regs.rdi = rdi;
	temp_regs.rsi = rsi;
	temp_regs.rdx = rdx;
	temp_regs.r10 = r10;
	temp_regs.r8 = r8;
	temp_regs.r9 = r9;

	// Replace original registers with manipulated ones.
	if (ptrace(PTRACE_SETREGS, pid, NULL, &temp_regs) == -1)
	{
		out_error("Pre-syscall PTRACE_SETREGS failed (errno = %d).\n", errno);
		return false;
	}

	// Execute the syscall and wait for it to finish.
	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1)
	{
		out_error("PTRACE_SYSCALL failed (errno = %d).\n", errno);
		return false;
	}
	if (!wait_child(pid))
	{
		out_error("waitpid failed (errno = %d).\n", errno);
		return false;
	}

	// Get the return value of the syscall.
	if (ptrace(PTRACE_GETREGS, pid, NULL, &temp_regs) == -1)
	{
		out_error("Post-syscall PTRACE_GETREGS failed (errno = %d).\n", errno);
		return false;
	}
	if (result)
	{
		*result = temp_regs.rax;
	}

	// Restore the original set of registers.
	orig_regs.rip -= 2; // Step back an instruction (syscall is 2 bytes long).
	orig_regs.rax = orig_regs.orig_rax; // For some reason this is required.
	if (ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs) == -1)
	{
		out_error("Post-syscall PTRACE_SETREGS failed (errno = %d).\n", errno);
		return false;
	}

	// Break at the current syscall again, as if nothing has happened.
	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1)
	{
		out_error("PTRACE_SYSCALL failed (errno = %d).\n", errno);
		return false;
	}
	if (!wait_child(pid))
	{
		out_error("waitpid failed (errno = %d).\n", errno);
		return false;
	}
	return true;
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Injects a read(2) syscall. Works exactly like read(2), except performed
*   on behalf of the child process. errno will be set to 800 if syscall
*   injection failed (eg: child terminated).
*
* Arguments
*   pid     - the child's process ID
*   [...]   - syscall arguments
*
* Returns
*   Same as read(2).
*
* Calls
*   inject_syscall
*
* Called by
*   parent_to_child
*   child_read
*
**************************************************************************/
ssize_t inject_read(pid_t pid, int fd, void *buf, size_t count)
{
	unsigned long result = 0;
	if (inject_syscall(pid, 0, fd, (unsigned long)buf, (unsigned long)count, 0, 0, 0, &result))
	{
		if (result > -4096ULL)
		{
			errno = -(int)result;
			return -1;
		}
		return (ssize_t)result;
	}
	else
	{
		errno = 800;
		return -1;
	}
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Injects a write(2) syscall. Works exactly like write(2), except
*   performed on behalf of the child process. errno will be set to 800 if
*   syscall injection failed (eg: child terminated).
*
* Arguments
*   pid     - the child's process ID
*   [...]   - syscall arguments
*
* Returns
*   Same as write(2).
*
* Calls
*   inject_syscall
*
* Called by
*   auto_dump
*   child_to_parent
*
**************************************************************************/
ssize_t inject_write(pid_t pid, int fd, const void *buf, size_t count)
{
	unsigned long result = 0;
	if (inject_syscall(pid, 1, fd, (unsigned long)buf, (unsigned long)count, 0, 0, 0, &result))
	{
		if (result > -4096ULL)
		{
			errno = -(int)result;
			return -1;
		}
		return (ssize_t)result;
	}
	else
	{
		errno = 800;
		return -1;
	}
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Injects an open(2) syscall. Works exactly like open(2), except
*   performed on behalf of the child process. errno will be set to 800 if
*   syscall injection failed (eg: child terminated).
*
* Arguments
*   pid     - the child's process ID
*   [...]   - syscall arguments
*
* Returns
*   Same as open(2).
*
* Calls
*   inject_syscall
*
* Called by
*   child_open
*
**************************************************************************/
int inject_open(pid_t pid, const char *pathname, int flags, mode_t mode)
{
	unsigned long result = 0;
	if (inject_syscall(pid, 2, (unsigned long)pathname, (unsigned long)flags, (unsigned long)mode, 0, 0, 0, &result))
	{
		if (result > -4096ULL)
		{
			errno = -(int)result;
			return -1;
		}
		return (int)result;
	}
	else
	{
		errno = 800;
		return -1;
	}
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Injects a close(2) syscall. Works exactly like close(2), except
*   performed on behalf of the child process. errno will be set to 800 if
*   syscall injection failed (eg: child terminated).
*
* Arguments
*   pid     - the child's process ID
*   [...]   - syscall arguments
*
* Returns
*   Same as close(2).
*
* Calls
*   inject_syscall
*
* Called by
*   get_mem_map
*   auto_dump
*
**************************************************************************/
int inject_close(pid_t pid, int fd)
{
	unsigned long result = 0;
	if (inject_syscall(pid, 3, fd, 0, 0, 0, 0, 0, &result))
	{
		if (result > -4096ULL)
		{
			errno = -(int)result;
			return -1;
		}
		return (int)result;
	}
	else
	{
		errno = 800;
		return -1;
	}
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Injects a lseek(2) syscall. Works exactly like lseek(2), except
*   performed on behalf of the child process. errno will be set to 800 if
*   syscall injection failed (eg: child terminated).
*
* Arguments
*   pid     - the child's process ID
*   [...]   - syscall arguments
*
* Returns
*   Same as lseek(2).
*
* Calls
*   inject_syscall
*
* Called by
*   auto_dump
*
**************************************************************************/
off_t inject_lseek(pid_t pid, int fd, off_t offset, int whence)
{
	unsigned long result = 0;
	if (inject_syscall(pid, 8, fd, (unsigned long)offset, (unsigned long)whence, 0, 0, 0, &result))
	{
		if (result > -4096ULL)
		{
			errno = -(int)result;
			return (off_t)-1;
		}
		return (off_t)result;
	}
	else
	{
		errno = 800;
		return (off_t)-1;
	}
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Injects an mmap(2) syscall. Works exactly like mmap(2), except
*   performed on behalf of the child process. errno will be set to 800 if
*   syscall injection failed (eg: child terminated).
*
* Arguments
*   pid     - the child's process ID
*   [...]   - syscall arguments
*
* Returns
*   Same as mmap(2).
*
* Calls
*   inject_syscall
*
* Called by
*   child_alloc
*
**************************************************************************/
void *inject_mmap(pid_t pid, void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	unsigned long result = 0;
	if (inject_syscall(pid, 9, (unsigned long)addr, (unsigned long)length, (unsigned long)prot, (unsigned long)flags, (unsigned long)fd, (unsigned long)offset, &result))
	{
		if (result > -4096ULL)
		{
			errno = -(int)result;
			return (void *)-1;
		}
		return (void *)result;
	}
	else
	{
		errno = 800;
		return (void *)-1;
	}
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Injects an munmap(2) syscall. Works exactly like munmap(2), except
*   performed on behalf of the child process. errno will be set to 800 if
*   syscall injection failed (eg: child terminated).
*
* Arguments
*   pid     - the child's process ID
*   [...]   - syscall arguments
*
* Returns
*   Same as munmap(2).
*
* Calls
*   inject_syscall
*
* Called by
*   child_free
*
**************************************************************************/
int inject_munmap(pid_t pid, void *addr, size_t length)
{
	unsigned long result = 0;
	if (inject_syscall(pid, 11, (unsigned long)addr, (unsigned long)length, 0, 0, 0, 0, &result))
	{
		if (result > -4096ULL)
		{
			errno = -(int)result;
			return -1;
		}
		return (int)result;
	}
	else
	{
		errno = 800;
		return -1;
	}
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Injects a readlink(2) syscall. Works exactly like readlink(2), except
*   performed on behalf of the child process. errno will be set to 800 if
*   syscall injection failed (eg: child terminated).
*
* Arguments
*   pid     - the child's process ID
*   [...]   - syscall arguments
*
* Returns
*   Same as readlink(2).
*
* Calls
*   inject_syscall
*
* Called by
*   child_readlink
*
**************************************************************************/
ssize_t inject_readlink(pid_t pid, const char *path, char *buf, size_t bufsiz)
{
	unsigned long result = 0;
	if (inject_syscall(pid, 89, (unsigned long)path, (unsigned long)buf, (unsigned long)bufsiz, 0, 0, 0, &result))
	{
		if (result > -4096ULL)
		{
			errno = -(int)result;
			return -1;
		}
		return (ssize_t)result;
	}
	else
	{
		errno = 800;
		return -1;
	}
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Allocates memory on behalf of the child.
*
* Arguments
*   pid     - the child's process ID
*   size    - the size of the memory to allocate
*
* Returns
*   Pointer to the allocated memory, or NULL on error.
*
* Calls
*   inject_mmap
*
* Called by
*   parent_to_child
*   child_read
*   child_readlink
*
**************************************************************************/
void *child_alloc(pid_t pid, size_t size)
{
	void *result = inject_mmap(pid, NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	return (result == (void *)-1) ? NULL : result;
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Frees allocated memory allocated by child_alloc on behalf of the child
*   process.
*
* Arguments
*   pid     - the child's process ID
*   ptr     - pointer to the memory to free
*   size    - size of the memory to free
*
* Returns
*   Nothing.
*
* Calls
*   inject_munmap
*
* Called by
*   child_open
*   child_read
*   child_readlink
*
**************************************************************************/
void child_free(pid_t pid, void *ptr, size_t size)
{
	inject_munmap(pid, ptr, size);
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Copies a memory buffer from the parent to the child process. You should
*   free the pointer returned by this function on behalf of the child
*   after you have finished using it. Assumes pipe capacity >= PIPE_SIZE
*   bytes.
*
* Arguments
*   pid     - the child's process ID
*   fds     - file descriptors of a pipe between the parent and the child
*   buff    - pointer to the buffer
*   length  - length of the buffer in bytes
*
* Returns
*   Pointer to the buffer in the child's address space.
*
* Calls
*   child_alloc
*   inject_read
*   child_free
*
* Called by
*   child_open
*   child_readlink
*
**************************************************************************/
void *parent_to_child(pid_t pid, int *fds, const void *buff, size_t length)
{
	void *result = child_alloc(pid, length);
	char *chbuf = (char *)result;
	if (!chbuf)
	{
		return NULL;
	}
	while (length)
	{
		size_t chunk = PIPE_SIZE < length ? PIPE_SIZE : length;
		size_t wr = (size_t)write(fds[1], buff, chunk);
		if (wr != chunk)
		{
			return NULL;
		}
		buff = (const char *)buff + wr;
		size_t rd = (size_t)inject_read(pid, fds[0], chbuf, wr);
		if (rd != wr)
		{
			return NULL;
		}
		chbuf += rd;
		length -= chunk;
	}
	return result;
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Copies a memory buffer from the child process to the parent. Assumes
*   pipe capacity >= PIPE_SIZE bytes.
*
* Arguments
*   pid     - the child's process ID
*   fds     - file descriptors of a pipe between the parent and the child
*   chptr   - pointer to the buffer in the child's address space
*   buff    - pointer to the buffer in the parent's address space
*   length  - length of the buffer in bytes
*
* Returns
*   Number of bytes copied.
*
* Calls
*   inject_write
*
* Called by
*   dbg_view
*   dbg_dump
*   child_read
*   child_readlink
*
**************************************************************************/
ssize_t child_to_parent(pid_t pid, int *fds, void *chptr, void *buff, size_t length)
{
	ssize_t count = 0;
	while (length)
	{
		size_t chunk = PIPE_SIZE < length ? PIPE_SIZE : length;
		size_t wr = (size_t)inject_write(pid, fds[1], chptr, chunk);
		if (wr != chunk)
		{
			return -1;
		}
		chptr = (char *)chptr + wr;
		size_t rd = (size_t)read(fds[0], buff, wr);
		if (rd != wr)
		{
			return -1;
		}
		buff = (char *)buff + rd;
		length -= chunk;
		count += (ssize_t)chunk;
	}
	return count;
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Injects an open(2) syscall. Uses the parent's address space for
*   pointers. errno not the same as the original syscall.
*
* Arguments
*   pid     - the child's process ID
*   fds     - file descriptors of a pipe between the parent and the child
*   [...]   - syscall arguments
*
* Returns
*   Same as open(2).
*
* Calls
*   child_alloc
*   inject_read
*   inject_open
*   child_free
*
* Called by
*   get_mem_map
*   auto_dump
*
**************************************************************************/
int child_open(pid_t pid, int *fds, const char *pathname, int flags, mode_t mode)
{
	size_t pathlen = strlen(pathname) + 1;
	char *chbuf = parent_to_child(pid, fds, pathname, pathlen);
	if (!chbuf)
	{
		return -1;
	}
	int result = inject_open(pid, chbuf, flags, mode);
	child_free(pid, chbuf, pathlen);
	return result;
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Injects a read(2) syscall. Uses the parent's address space for
*   pointers. errno not the same as the original syscall.
*
* Arguments
*   pid     - the child's process ID
*   fds     - file descriptors of a pipe between the parent and the child
*   [...]   - syscall arguments
*
* Returns
*   Same as read(2).
*
* Calls
*   child_alloc
*   inject_read
*   inject_write
*   child_free
*
* Called by
*   get_mem_map
*
**************************************************************************/
ssize_t child_read(pid_t pid, int *fds, int fd, void *buf, size_t count)
{
	char *chbuf = (char *)child_alloc(pid, count);
	if (!chbuf)
	{
		return -1;
	}
	if (inject_read(pid, fd, chbuf, count) == -1)
	{
		return -1;
	}
	ssize_t result = child_to_parent(pid, fds, chbuf, buf, count);
	child_free(pid, chbuf, count);
	return result;
}

/************************* PUBLIC FUNCTION ********************************
*
* Description
*   Injects a readlink(2) syscall. Uses the parent's address space for
*   pointers. errno not the same as the original syscall.
*
* Arguments
*   pid     - the child's process ID
*   fds     - file descriptors of a pipe between the parent and the child
*   [...]   - syscall arguments
*
* Returns
*   Same as readlink(2).
*
* Calls
*   parent_to_child
*   child_alloc
*   inject_readlink
*   inject_write
*   child_free
*   child_to_parent
*
* Called by
*   auto_dump
*
**************************************************************************/
ssize_t child_readlink(pid_t pid, int *fds, const char *path, char *buf, size_t bufsiz)
{
	ssize_t result = -1;
	size_t pathlen = strlen(path) + 1;
	char *chpath = parent_to_child(pid, fds, path, pathlen);
	if (chpath)
	{
		char *chbuf = child_alloc(pid, bufsiz);
		if (chbuf)
		{
			result = inject_readlink(pid, chpath, chbuf, bufsiz);
			if (result != -1)
			{
				if (child_to_parent(pid, fds, chbuf, buf, bufsiz) == -1)
				{
					result = -1;
				}
			}
			child_free(pid, chbuf, bufsiz);
		}
		child_free(pid, chpath, pathlen);
	}
	return result;
}
