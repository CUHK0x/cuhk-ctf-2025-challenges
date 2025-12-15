#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int main();

void _start() {
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SYS_read, 8, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SYS_write, 7, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SYS_fstat, 6, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SYS_newfstatat, 5, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SYS_getrandom, 4, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SYS_brk, 3, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SYS_exit, 2, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SYS_exit_group, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog arg = {
        .len = (sizeof(filter) / sizeof(filter[0])),
        .filter = filter
    };
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &arg)) {
        perror("seccomp");
        puts("This is unintended. Contact challenge author.");
    }
    clearenv(); // hot fix
    syscall(SYS_exit, (unsigned char)main());
}
