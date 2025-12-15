from Crypto.Util.number import long_to_bytes
from pwn import *

with remote("localhost", 25058) as io: # Change to the appropriate host and port
    io.recvuntil(b"n: ")
    n = int(io.recvline().strip())
    io.recvuntil(b"c: ")
    c = int(io.recvline().strip())
    r = 2

    io.sendlineafter(b"c1: ", str(n - 1).encode())
    io.sendlineafter(b"c2: ", str(r * c % n).encode())
    io.recvuntil(b"m: ")
    mrd = int(io.recvline().strip()) ^ (n - 1) # mrd = m * r ** d = decrypt(r * c)

    io.sendlineafter(b"c1: ", str(n - r * c % n).encode())
    io.sendlineafter(b"c2: ", str(r).encode())
    io.recvuntil(b"m: ")
    rd = int(io.recvline().strip()) ^ (n - mrd) # rd = r ** d

    flag = long_to_bytes(mrd * pow(rd, -1, n) % n)

    print(flag.decode())
    io.close()