## \[Crypto] Secret Base
> Expected Difficulty: 2

Note: To avoid ambiguity, in this writeup, we will use `**` to denote exponentiation, `^` to denote bitwise XOR.

This challenge is a simple RSA challenge. Let's first have a look at the code.

```python
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
```

There is no obvious vulnerability here. `e` is not fixed to a common value like `65537`. It is worth noting that `e` is an odd integer, and `phi` is an even integer. We can deduce that `d` is also an odd integer.

```python
flag = open("flag.txt", "rb").read().strip()
secret_base = int.from_bytes(flag, "big")
assert 0 < secret_base < n
c = encrypt(secret_base) # The unknown base of RSA is a secret base, right? :3
s = set([c])
print(f"n: {n}")
print(f"c: {c}")
```
You are given `n` and `c`. Notice that `e` is unknown, and `c` is the ciphertext to be cracked.

```python
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
```
You can query the server with two ciphertexts `c1` and `c2`, and it will return `m1 ^ m2`, where `m1` and `m2` are the decrypted plaintexts of `c1` and `c2`, respectively.

More importantly, you cannot reuse the same ciphertext for multiple queries.

It is also worth noting that the assertion also bans `1` and `c` from being queried.

Why is 1 and c banned?

It is a bit strange that a specific value is banned. It is easy to understand why `c` is banned since decrypting `c` is our goal.

`1` is a special value in RSA. Decrypting `1` will always yield `1`, regardless of the values of `d` and `n`. This is because `1**d mod n = 1`.

But this is banned... can we find another value that have similar property?

Let's try `-1` (or `n-1` under modulo `n`). `-1**d mod n = -1 mod n = n-1` since `d` is odd.

We have just seen that `decrypt(1) = 1` and `decrypt(-1) = -1`. (should be `n-1` under modulo `n`, but we will just use `-1` so that it is easier to understand)

That is, if we query `c1 = n-1` then we can arbitrarily decrypt any ciphertext `c2` by xoring the result with `n-1`.

But we don't have information about decrypting `c` since using `c` itself is banned.

Instead of going for `c`, we can use `-c` (or `n-c` under modulo `n`) instead. `(-c) ** d mod n = (-1 ** d) * (c ** d) mod n = -f mod n = n-f`, where `f` is the flag.

So, we just have to query `c1 = n-1` and `c2 = n-c` to get `m`, and the flag is `n - (m ^ (n-1))`.

Code:

```python
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
```