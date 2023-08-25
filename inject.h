#ifndef INJECT_H
#define INJECT_H

#include <stdbool.h>
#include <sys/types.h>

/* DATA STRUCTURES */
typedef struct
{
    bool chkrdi;
    bool chkrsi;
    bool chkrdx;
    bool chkr10;
    bool chkr8;
    bool chkr9;
    unsigned long rdi;
    unsigned long rsi;
    unsigned long rdx;
    unsigned long r10;
    unsigned long r8;
    unsigned long r9;
} brkcond_t;

/* SYSCALL MANIPULATION API */
bool break_at_syscall(long id, pid_t pid, brkcond_t conditions);
bool inject_syscall(pid_t pid, unsigned long rax, unsigned long rdi, unsigned long rsi, unsigned long rdx, unsigned long r10, unsigned long r8, unsigned long r9, unsigned long *result);

/* RAW SYSCALLS (USES CHILD'S ADDRESS SPACE FOR POINTERS) */
ssize_t inject_read(pid_t pid, int fd, void *buf, size_t count);
ssize_t inject_write(pid_t pid, int fd, const void *buf, size_t count);
int inject_open(pid_t pid, const char *pathname, int flags, mode_t mode);
int inject_close(pid_t pid, int fd);
off_t inject_lseek(pid_t pid, int fd, off_t offset, int whence);
void *inject_mmap(pid_t pid, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int inject_munmap(pid_t pid, void *addr, size_t length);
ssize_t inject_readlink(pid_t pid, const char *path, char *buf, size_t bufsiz);

/* PARENT-CHILD COMMUNICATION HELPERS */
void *child_alloc(pid_t pid, size_t size);
void child_free(pid_t pid, void *ptr, size_t size);
void *parent_to_child(pid_t pid, int *fds, const void *buff, size_t length);
ssize_t child_to_parent(pid_t pid, int *fds, void *chptr, void *buff, size_t length);

/* CHILD SYSCALLS (USES PARENT'S ADDRESS SPACE FOR POINTERS) */
int child_open(pid_t pid, int *fds, const char *pathname, int flags, mode_t mode);
ssize_t child_read(pid_t pid, int *fds, int fd, void *buf, size_t count);
ssize_t child_readlink(pid_t pid, int *fds, const char *path, char *buf, size_t bufsiz);

#endif /* INJECT_H */
