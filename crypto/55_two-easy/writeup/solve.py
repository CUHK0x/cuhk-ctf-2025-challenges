from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from tqdm import tqdm

# Constants
ENCRYPTED_FLAG = bytes.fromhex(
    "aa5f9a2a140bb018146632527270b364e56ee406760dad00229b33d1c71a5ae07a869bf26cd1790a1da8ad4be0ce5bd548bcda2d5917e23067846db51d67380d"
)

KNOWN_PADDING = b"\x10" * 16

middle_dict = {}

# Encrypt the padding with every possible key
# Memorize the corresponding key of a result with `middle_dict`
for i in tqdm(range(1 << 24)):
    key = i.to_bytes(3) + b"\x69" * 13
    cipher = AES.new(key, AES.MODE_ECB)
    middle_dict[cipher.encrypt(KNOWN_PADDING)] = key

# Decrypt the first block with every possible key until
# the decryption result is found in the `middle_dict`
for i in tqdm(range(1 << 24)):
    key_2 = i.to_bytes(3) + b"\x96" * 13
    cipher_2 = AES.new(key_2, AES.MODE_ECB)
    mid = cipher_2.decrypt(ENCRYPTED_FLAG[-16:])

    if mid in middle_dict:
        # Both keys are found here
        # Simply reverse the encryption process here
        key_1 = middle_dict[mid]
        cipher_1 = AES.new(key_1, AES.MODE_ECB)
        cipher_2 = AES.new(key_2, AES.MODE_ECB)
        flag = cipher_1.decrypt(cipher_2.decrypt(ENCRYPTED_FLAG))
        print(unpad(flag, 16))
        break