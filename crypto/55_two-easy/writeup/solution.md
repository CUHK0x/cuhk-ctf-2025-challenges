# two easy

> - Author: sup
> - Difficulty: 2/5
>
> Flag: cuhk25ctf{me37_1n_7h3_m1dd13_g0e5_8rrr_4bb4fb81}

Reading the script, we can see that the program uses two 24-bit key in a chained AES cipher (in ECB mode). The program first encrypts the flag with the first key, then the second key. It may seem like there is an effectively 48-bit key space for us to search for, which is computationally impossible at least on our computers. However, a meet-in-the-middle trick here can dramatically decrease the key space down to only 25-bit.

Let our message be M, key 1 be k1, key 2 be k2. Now, we know C = AES-encrypt(AES-encrypt(M, k1), k2). Notice that AES-decrypt(C, k2) = AES-encrypt(M, k1). If we **know** a pair of M and C, we can brute-force the result of all the possible keys in LHS and RHS **independently** within a reasonable time (each side around 2 to 3 minutes). Then, we can find the key-pair that fulfill the above equalities. Finally, we can use this key-pair to decrypt the encrypted flag.

However, it seems like we don't really have a known plaintext-ciphertext pair. Although we cannot have custom input to the encryption process, we can notice that the length of the flag is a multiple of 16, and hence the flag is padded with an extra 16 bytes of `b'\x10'` before encryption. With this knowledge, we basically have a known plaintext (the padding) and ciphertext pair (the last 16 bytes of the encrypted flag). From here, we can continue on the above attack.

Unprofessionally and statistically speaking, since there are ![equation](<https://latex.codecogs.com/svg.image?(2^8)^{16}>) possible results for both LHS and RHS, and there are ![equation](<https://latex.codecogs.com/svg.image?(2^8)^3>) keys, the chance of getting an equality is:

![equation](<https://latex.codecogs.com/svg.image?\frac{(2^8)^3}{(2^8)^{16}}=2^{-104}\approx&space;0>)

which is basically almost impossible. Hence, we can be very confident that the key pair we get from the above process is the only one that fulfills the equation.