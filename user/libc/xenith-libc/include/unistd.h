#ifndef XENITH_UNISTD_H
#define XENITH_UNISTD_H
#include <stddef.h>
typedef long ssize_t;
#define GRND_NONBLOCK 1u
ssize_t xenith_write(int fd, const void *buffer, size_t count);
ssize_t xenith_read(int fd, void *buffer, size_t count);
int xenith_close(int fd);
int xenith_dup(int fd);
int xenith_dup2(int old_fd, int new_fd);
int xenith_pipe(int descriptors[2]);
int xenith_openpty(int descriptors[2]);
int xenith_setpgid(long pid, long process_group);
long xenith_getpgrp(void);
long xenith_setsid(void);
int xenith_kill(long pid, unsigned int signal);
ssize_t xenith_ioctl(int fd, unsigned int command, size_t argument);
ssize_t xenith_getrandom(void *buffer, size_t count, unsigned int flags);
_Noreturn void xenith_exit(int status);
#endif
