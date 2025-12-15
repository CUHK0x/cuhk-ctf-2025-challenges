from Crypto.Util.number import getPrime, bytes_to_long


flag = b"cuhk25ctf{fake-flag}"

p1 = getPrime(512)
q1 = getPrime(512)
n1 = p1 * q1

p2 = getPrime(512)
q2 = getPrime(512)
n2 = p2 * q2

p3 = getPrime(512)
q3 = getPrime(512)
n3 = p3 * q3
e = 5

ciphertext1 = pow(bytes_to_long(flag), e, n1)
ciphertext2 = pow(bytes_to_long(flag), e, n2)
ciphertext3 = pow(bytes_to_long(flag), e, n3)

print(f"{e = }")
print(f"{n1 = }")
print(f"{ciphertext1 = }")
print(f"{n2 = }")
print(f"{ciphertext2 = }")
print(f"{n3 = }")
print(f"{ciphertext3 = }")
