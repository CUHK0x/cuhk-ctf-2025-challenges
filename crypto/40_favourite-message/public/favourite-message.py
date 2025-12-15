from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


class Cipher:
    def __init__(self, key):
        self.key = key

    def encrypt_block(self, block):
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(block)

    def encrypt(self, message):
        assert len(message) % 16 == 0
        blocks = [message[i : i + 16] for i in range(0, len(message), 16)]
        encrypted_message = b""
        for plaintext in blocks:
            ciphertext = self.encrypt_block(plaintext)
            self.key = xor(plaintext, ciphertext)
            encrypted_message += ciphertext
        return encrypted_message


def main():
    UwU = os.urandom(16)
    cipher = Cipher(UwU)

    print("Let's exchange our favourite messages!")
    message = input("Tell me your favourite message: ").encode()

    print("This message looks cool! ^v^")

    flag = open("flag.txt", "rb").read()
    message = message.replace(b"{flag}", flag)
    message += b"UwU"
    message = message.replace(b"UwU", b"UwU"*4) # More UwU!! Make sure the UwU is UwU enough!
    message = pad(message, 16)

    print("And here is my favourite message! I am sure you will UwU it!")
    print("UwU", cipher.encrypt(message).hex())
    

if __name__ == "__main__":
    main()
