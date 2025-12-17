#include "seccomp-bpf.h"

static int setup()
{
    setvbuf(stdin, NULL, 2, 0);
    setvbuf(stdout, NULL, 2, 0);
    setvbuf(stderr, NULL, 2, 0);
    struct sock_filter filter[] = 
    {
        /* Validate architecture. */
        VALIDATE_ARCHITECTURE,
        /* Grab the system call number. */
        EXAMINE_SYSCALL,
        BLOCK_X32_SYSCALL,
        /* List blocked syscalls. */
        BLOCK_SYSCALL(execve),
        BLOCK_SYSCALL(open),
        ALLOW_PROCESS,
    };

    struct sock_fprog prog = 
    {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
    };

    if ( prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ) 
    {
        perror(":c");
        goto failed;
    }
    if ( prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) ) 
    {
        perror(":<");
        goto failed;
    }
    return 0;

failed:
    if ( errno == EINVAL )
    {
        printf(":(\n");
    }

    return 1;
}

void fun() {
    char compartment[0x88];
    unsigned long long *cost = compartment + 0x88;
    printf("I have a compartment available for renting at %p, but I bet you cannot find my secret compartment\n", &compartment);
    printf("I can rent you some space to put things in this compartment though.\n");
    printf("You are lucky that I am making a limited time offer, just HKD %p for 0x88 bytes storage!\n", *cost);
    gets(compartment);
}

int main() {
    setup();
    fun();
}