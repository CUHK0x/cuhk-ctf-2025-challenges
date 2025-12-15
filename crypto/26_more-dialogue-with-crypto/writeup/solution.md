# More Dialogue with Crypto

> - Author: sup
> - Difficulty: 2/5
>
> Flag: cuhk25ctf{Z4_p0w3r_0f_Ch1n35e_r3M4iNd3r_7h30r3m!!111!!!}

Looking at the script, we know that each ciphertext we see in output.txt is encrypted with RSA, with different n correspondingly. Since we have multiple ciphertext-n pairs, we can use the Chinese Remainder Theorem to find out `flag`^e mod (n1 \* n2 \* n3). For more details, checkout this [Wikipedia Page](https://en.wikipedia.org/wiki/Chinese_remainder_theorem).

With the above knowledge, we can make the following script to attempt to decrypt the message.

```py
m1 = n2 * n3
m2 = n1 * n3
m3 = n1 * n2

t1 = inverse(m1, n1)
t2 = inverse(m2, n2)
t3 = inverse(m3, n3)

ciphertext = (ciphertext1 * m1 * t1 + ciphertext2 * m2 * t2 + ciphertext3 * m3 * t3) % (n1 * n2 * n3)
```

Notice that `ciphertext` may not be `flag`^e when the latter is larger than (n1 \* n2 \* n3). However, since e = 5 is small, we may still ~~hope that `flag`^5 is smaller than that and~~ try finding the 5-th root. In this case, the flag is actually not too long and we can find the exact 5-th root of ciphertext. Finally, we can convert this number back to bytes and we obtain the flag.