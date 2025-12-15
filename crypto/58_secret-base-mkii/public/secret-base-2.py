from Crypto.Util.number import getPrime
from Crypto.Random.random import randint
from math import gcd

p = getPrime(1024)
q = getPrime(1024)
n = p * q
phi = (p - 1) * (q - 1)
e = phi
while gcd(e, phi) != 1:
    e = randint(2, phi - 1)
    if e % 2 == 0:
        e += 1
d = pow(e, -1, phi)

def encrypt(m):
    return pow(m, e, n)

def decrypt(c):
    return pow(c, d, n)

def main():
    flag = open("flag.txt", "rb").read().strip()
    secret_base = int.from_bytes(flag, "big")
    assert 0 < secret_base < n
    c = encrypt(secret_base) # The unknown base of RSA is a secret base, right? :3
    s = set([c, n - c]) # UwU
    print(f"n: {n}")
    print(f"c: {c}")

    while True:
        c1 = int(input("c1: "))
        assert 1 < c1 < n, "u h4cker!"
        assert c1 not in s, ":<"
        s.add(c1)
        
        c2 = int(input("c2: "))
        assert 1 < c2 < n, "u h4cker!"
        assert c2 not in s, ":<"
        s.add(c2)

        m1 = decrypt(c1)
        m2 = decrypt(c2)
        
        print(f"m: {m1 ^ m2}")


if __name__ == "__main__":
    main()
