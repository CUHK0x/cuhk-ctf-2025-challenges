For all: Flag can be accessed with environment variable in the submitted program
Solution 1: Leak flag through stderr
Solution 2: Actually solve the challenge and give the flag
Solution 3: Write to opened file descriptors
Solution 4: Write to challenge script to leak the flag
Solution 5: Fork an orphan and do something

# Design
1. Flag in file or envvar?
    - File: Read from unclosed file in `entrypoint.c` (or the shell script, since they are both parent process of the user code) (What is the legitimate purpose to read the flag in `entrypoint.c`, when we have already generated the testcases?)
    - Envvar: Read directly from memory where the envvar is pushed
    - [x] Process memory: If `entrypoint.c` is implemented to embed in the user program, memory used by `entrypoint.c` is readable by user program
2. How to leak the flag?
    - Write to some kind of file then use another vulnerability to read it:
        - [x] If leak compiler message --> arbitrary read. Use hash of C source as submission id to have predictable file name!
        - If leak diff --> just output
        - Write to test cases: Cannot write to file opened with `< file`
    - File descriptors opened in the user's program:
        - Leak through `stderr`
        - Provide other file descriptors
            - copy the TCP output stream to user's program (`stderr` already satisfies)
    - Side Channels (unlikely)
3. Change source script so that the user code spawns with `execve`? Can't dig process memory?

# Checklist
- [ ] Remove `set -u` and comments

# Questions
Will a child process get the environment variable if the parent has called `unsetenv` on the variable? No. (Tested with `system("env")`. If `execve` is used should depend on the `envp` parameter.)