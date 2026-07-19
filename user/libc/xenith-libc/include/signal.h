#ifndef XENITH_SIGNAL_H
#define XENITH_SIGNAL_H

#include <stddef.h>

#define SIG_DFL 0ul
#define SIG_IGN 1ul

#define SIG_BLOCK 0u
#define SIG_UNBLOCK 1u
#define SIG_SETMASK 2u

#define SA_SIGINFO 0x00000004ul
#define SA_ONSTACK 0x08000000ul
#define SA_RESTART 0x10000000ul
#define SA_NODEFER 0x40000000ul
#define SA_RESETHAND 0x80000000ul

#define SS_ONSTACK 1u
#define SS_DISABLE 2u
#define MINSIGSTKSZ 16384ul
#define MAXSIGSTKSZ (8ul * 1024ul * 1024ul)

#define SI_USER 0
#define SI_KERNEL 128

typedef unsigned long sigset_t;

struct sigaction {
    unsigned long sa_handler;
    sigset_t sa_mask;
    unsigned long sa_flags;
};

typedef struct {
    void *ss_sp;
    size_t ss_size;
    unsigned int ss_flags;
    unsigned int __reserved;
} stack_t;

typedef struct {
    unsigned int si_signo;
    int si_code;
    int si_errno;
    unsigned int si_trapno;
    unsigned long si_addr;
    unsigned long si_pid;
    unsigned long si_uid;
    long si_status;
    unsigned long si_value;
    unsigned long __reserved;
} siginfo_t;

typedef struct {
    unsigned long signo;
    sigset_t saved_mask;
    unsigned long rip, cs, rflags, rsp, ss;
    unsigned long rax, rbx, rcx, rdx, rsi, rdi, rbp;
    unsigned long r8, r9, r10, r11, r12, r13, r14, r15;
    siginfo_t info;
    unsigned long xstate_ptr;
    unsigned long xstate_size;
    unsigned long xstate_features;
    unsigned long frame_flags;
} xenith_ucontext_t;

int xenith_sigaction(unsigned int signal, const struct sigaction *action,
                     struct sigaction *old_action);
int xenith_sigprocmask(unsigned int how, const sigset_t *set, sigset_t *old_set);
int xenith_sigaltstack(const stack_t *new_stack, stack_t *old_stack);

#endif
