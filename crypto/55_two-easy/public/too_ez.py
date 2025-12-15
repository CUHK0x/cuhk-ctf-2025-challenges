import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

with open("flag.txt", "rb") as f:
    flag = f.readline().strip()
    assert len(flag) % 16 == 0


def main():
    # This "48-bit" encryption is impossible to crack, right?
    key_1 = os.urandom(3) + b"\x69" * 13
    key_2 = os.urandom(3) + b"\x96" * 13

    cipher_1 = AES.new(key_1, AES.MODE_ECB)
    cipher_2 = AES.new(key_2, AES.MODE_ECB)
    encrypted = cipher_2.encrypt(cipher_1.encrypt(pad(flag, 16))).hex()
    print("Flag:", encrypted)


if __name__ == "__main__":
    main()
