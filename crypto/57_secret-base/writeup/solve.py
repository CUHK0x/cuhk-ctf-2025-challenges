from Crypto.Util.number import long_to_bytes
from pwn import *

with remote("localhost", 25057) as io: # Change to the appropriate host and port
    io.recvuntil(b"n: ")
    n = int(io.recvline().strip())
    io.recvuntil(b"c: ")
    c = int(io.recvline().strip())
    
    io.sendlineafter(b"c1: ", str(n-1).encode())
    io.sendlineafter(b"c2: ", str(n-c).encode())

    io.recvuntil(b"m: ")
    m = int(io.recvline().strip())
    flag = long_to_bytes(n-(m ^ (n-1)))

    print(flag.decode())
    io.close()