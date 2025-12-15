## \[Crypto] Secret Base MKII
> Expected Difficulty: 3

Note: To avoid ambiguity, in this writeup, we will use `**` to denote exponentiation, `^` to denote bitwise XOR.

Before reading this writeup, it is recommended to read the writeup for [Crypto] Secret Base first, as this challenge is a harder version of that challenge.

Only 1 line of code is changed from the previous challenge:

```python
s = set([c, n - c]) # UwU
```

This time, `-c` is banned too. So the previous attack no longer works. Still, `-1` is not banned and we can still decrypt arbitrary ciphertexts... at least we can do it once.

While this may be a bit difficult to solve, let's consider a slightly easier version of this challenge. What if `e` is given to you?

If we have `e`, we can make use of RSA Blinding Attack to decrypt `c`. The idea is as follows:
1. Pick a random integer `k` such that `1 < k < n`.
2. Compute `c' = (k ** e * c) % n`.
3. Query the server with `c1 = n - 1` and `c2 = c'`. The server will return `m1 ^ m2 = (n - 1) ^ decrypt(c') = (n - 1) ^ (f * k)`.
4. Xor the result with `n - 1` to get `f * k`.
5. With `f * k`, we can compute `f` by multiplying it with the modular inverse of `k` modulo `n`.
6. We can get the flag!

Unfortunately, we don't know `e`.

Let's find other things that we can do. Can we decrypt more than one ciphertext?

We know that `decrypt(c) = - decrypt(-c)`. With our first query `c1 = n - 1`, we can decrypt an arbitrary ciphertext `c2` to get `m2 = decrypt(c2)`. Then we automatically know that `decrypt(n - c2) = n-m2`, so if we use `n-c2` as the new `c1` in our next query, we can decrypt another arbitrary `c2`. This chain can keep going on and on, and we can decrypt as many ciphertexts as we want.

Now, we can decrypt multiple ciphertexts, can we use this to carry out a similar blinding attack?

It is actually possible. This time, we don't choose a random `k`, we choose a random `r` such that `r = k ** e % n`. It is fine that we don't know `k`. The important thing is that `decrypt(r) = k` and we know `r`.

So in our first query, we can use `c1 = n - 1` and `c2 = r * c % n` to get `mrd = decrypt(r * c) = decrypt(r) * decrypt(c) = k * f`. And in our second query, we can use `c1 = n - r * c % n` and `c2 = r` to get `rd = decrypt(r) = k`. Finally, we can compute `f = mrd * pow(rd, -1, n) % n` to get the flag.

Code:
```python
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
```