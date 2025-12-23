from pwn import *
from collections import defaultdict

dct = defaultdict(lambda: [0, 0])

flag_length = None
flag = b""

conn = remote("localhost", 25060)
try:
    while True:
        conn.recvuntil(b"here you go... ").decode()
        
        encrypted = conn.recvline()[2:-1].decode()
        print(bytes.fromhex(encrypted))

        flag_length = len(encrypted) // 2
        encrypted = int(encrypted, 16)

        for i in range(8 * flag_length):
            dct[i][(encrypted & (1 << i)) >> i] += 1

        flag_binary = "".join("0" if zero > one else "1" for zero, one in dct.values())[::-1]
        flag = int.to_bytes(int(flag_binary, 2), flag_length, "big")
        print(flag)

        conn.recvuntil(b"I will check if you are right.\n")
        conn.sendline(flag)
        
        assert len(flag) == flag_length
except EOFError:
    print("Decrypted flag:", flag.decode())
