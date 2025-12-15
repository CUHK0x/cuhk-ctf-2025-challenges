from pwn import *
from collections import defaultdict

dct = defaultdict(lambda: [0, 0])

flag_length = None
flag = b""

conn = remote("localhost", 25060)
for _ in range(50):
    conn.recvuntil(b"here you go... ")
    encrypted = conn.recvline()[:-1]
    print(encrypted)

    flag_length = (len(encrypted) - 2) // 2
    for idx, x in enumerate(encrypted[2:].decode()):
        for i in range(4):
            dct[4 * idx + i][(int(x, 16) & (1 << (3 - i))) >> (3 - i)] += 1

    conn.recvuntil(b"I will check if you are right.\n")
    conn.sendline(b"hello bob")

    flag_binary = "".join("0" if zero > one else "1" for zero, one in dct.values())
    flag = int.to_bytes(int(flag_binary, 2), flag_length, "big")
    print(flag)

flag_binary = "".join("0" if zero > one else "1" for zero, one in dct.values())
flag = int.to_bytes(int(flag_binary, 2), flag_length, "big")

conn.recvuntil(b"I will check if you are right.\n")
conn.sendline(flag)
conn.interactive()