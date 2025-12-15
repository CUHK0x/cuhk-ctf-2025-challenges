from pwn import *
from Crypto.Cipher import AES

with remote("localhost", 25040) as io: # Change to the appropriate host and port
    io.sendlineafter(b"Tell me your favourite message: ",b"0" * 16 + b"{flag}")
    io.recvuntil(b"\nUwU ")
    c = bytes.fromhex(io.recvline().strip().decode())
    key = xor(b"0" * 16, c[:16])
    m = b""
    for i in range(16, len(c), 16):
        cipher = AES.new(key, AES.MODE_ECB)
        block = c[i : i + 16]
        b = cipher.decrypt(block)
        m += b
        key = xor(b, block)
    print(m)