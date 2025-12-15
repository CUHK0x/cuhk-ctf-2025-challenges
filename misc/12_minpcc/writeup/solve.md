# Challenge Overview
The challenge is a shell script served over a TCP connection. The user can supply a C source code file, then the script will compile and execute it, and compare the output with the correct answer. The usual C program entry point supplied by from libc is replaced with a custom one, which a `seccomp` filter is installed and `clearenv` is called to remove environment variables of the program.

# Insight
Before we start investigating, anyone who know a little about cryptography knows that the SHA256 hash function is not reversable. In addition, the program does not give you the flag when you have an accepted program. Completing the assignment does nothing to obtain the flag.

Firstly, notice that the existence of the `FLAG` variable is checked in `start.sh`. Since there is no previous definition of `FLAG` in the shell script, this implies that `FLAG` must be an environment variable of the container. And since the environment variable is not explicitly removed before executing the user-supplied program, this means that the user supplied program can read the `FLAG` environment variable.

However, there are two countermeasures that prevents the user from obtaining the flag. First, there is a seccomp filter in-place that prevents the user from leaking the flag through conventional methods such as a remote shell. The seccomp filter is set in the `_start` function so that it is the first code to be executed in the executable, and the filter code is placed in a separate source file (a separate "*compilation unit*" in compiler terminology) so that you can not remove the seccomp filter just by simply `#define`ing away the `_start` function and provide your own. Secondly, environment variables are cleared with `clearenv`, so that one cannot simply use `getenv` to obtain the `FLAG` environment variable (but you will later see why this is circumventable).

One with some low level knowledge on how Linux executables work can observe that both measures are inadequate to prevent the user from accessing the flag variable. For starters, the `clearenv` function only clears the heap variable `environ`, used by glibc functions like `getenv` to access environment variables in the entire executable. But the environment variables are pushed to the stack by the time the program is executed. This means despite `environ` being cleared, **you can search for the `FLAG` environment variable in the stack**. This is also possible due to the setup code being placed in the same executable as the user supplied code, the stack is persisted.

The question then, is how to leak the flag. Observe that `&>` is used to direct output, so both `stdout` and `stderr` is directed to the output text file.[^1] There is not other file descriptor open. Then we notice the output file has a predictable name (SHA256 hash of the source), and is persisted on the server. Plus, the `gcc` output is not silenced, unlike the diff and user program. By using the `#include` preprocessor directive of the C language, we can read any file on the host. **We can then use it to the read the flag that we have output in our program.**

# Solution
1. Craft the C program:
    1. Search for the string `FLAG` in the stack. The environment variable will be stored in a format like `FLAG=cuhkctf{...}\0`
    2. Output the string
2. Compute the SHA256 hash of the source file[^2], and include its output by `#include "../out/<hash>.out"`
3. Read the error message generated and profit.

# Trivia
- This challenge may or may not be inspired by **PC^2**, the programming challenge judge used for competitive programming contests.
- The original solution was just having the user source code appended to the driver code, so the challenge can be solved by bypassing the seccomp filter.
- The multiple allowed syscalls are so that regular glibc non-file IO does not fail.

[^1]: If `stderr` is not redirected, `stderr` will be connected to the user's IO and output to `stderr` will print to the user's console.
[^2]: When the source code is saved to a file with `echo $SRC > $SRC_PATH`, the `echo` command adds an extra newline, so the hash is the original source plus an additional newline.