from pwn import *
from SquigglyStuff import Squiggle, Point, deserialize_point
# from tqdm import tqdm

# Precompute some useful results (you can use sage to do this)
p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
a = 0
# b is variable...
# F = GF(p)
# E = EllipticCurve(F, [a, b])
# G = E(x, y)
# factor(G.order()) # Factorize the order of the point G, which is also a factor of the order of the curve

# def exploit(x, y):
#     b = (y^2 - x^3) % p
#     if b == 0:
#         return
#     E = EllipticCurve(F, [0, b])
#     G = E(x, y)
#     order = G.order()
#     print(b, order, factor(order), (x, y))

# The equation of the curve is y^2 = x^3 + b since a = 0
# We just need to find some good b values
exploitation_list = [
    # (order, factors, Generator)
    (115792089237316195423570985008687907853031073199722524052490918277602762621571, [109903, 12977017, 383229727], Point(1, 2)),
    (57896044618658097711785492504343953926299326406578432197819248705606044722122, [2 * 20412485227], Point(1, 3)),
    (38597363079105398474523661669562635951234135017402074565436668291433169282997, [3 * 13 * 13 * 3319, 22639], Point(1, 4)),
    (38597363079105398474523661669562635951169632043852868008808083246071635573919, [199 * 18979], Point(2, 34)),
    (4135431758475578407984678036024568137640761304218723702974166807307342139253, [7 * 10903, 5290657, 10833080827], Point(1, 7)),
]
target = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
E = Squiggle(a, 7, p)
Generator = Point(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

# context.log_level = 'debug'
with remote('localhost', 25059) as io:
    information = []
    io.recvuntil(b"Q: ")
    
    Q = deserialize_point(io.recvline().strip().decode())
    log.info(f"Q = dG = {Q}")

    def bsgs(P, G, order):
        log.info(f"Using BSGS to solve for P = kG, P = {P}, G = {G}, k < {order}")
        sqrt_order = int(order**0.5) + 1
        neg_G = E.negate(G)
        table = dict()
        for i in range(sqrt_order):
            table[P] = i
            P = E.add(P, neg_G)

        larger_G = E.mul(sqrt_order, G)
        Acc = Point(None, None)
        for j in range(sqrt_order):
            if Acc in table:
                return (j * sqrt_order + table[Acc]) % order
            Acc = E.add(Acc, larger_G)
        log.error("No solution found when running BSGS")
        return None

    def exploit(order, factor, G):
        if E.mul(order // factor, G) == Point(None, None):
            return None
        io.recvuntil(b"> ")
        io.sendline(b"n")
        io.sendlineafter(b"C1: ", str(E.mul(order // factor, E.negate(G))).encode())
        io.sendlineafter(b"C2: ", str(Point(None, None)).encode())
        io.recvuntil(b"The thing you need is ")
        P = deserialize_point(io.recvline().strip().decode()) # P = -d * C1 = d * G
        # print("Received P:", P, flush=True)

        residue = bsgs(P, E.mul(order // factor, G), factor)
        return (residue, factor) # d % factor = residue

    for order, factors, G in exploitation_list:
        for factor in factors:
            result = exploit(order, factor, G)
            if result is not None:
                information.append(result)
                log.info(f"Found: d mod {factor} = {result[0]}")

    def crt(information):
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        def mod_inverse(a, m):
            gcd, x, _ = extended_gcd(a, m)
            if gcd != 1:
                raise ValueError("Inverse doesn't exist")
            return x % m
        def combine(a1, m1, a2, m2):
            gcd, x, y = extended_gcd(m1, m2)
            if (a1 - a2) % gcd != 0:
                raise ValueError("No solution exists")
            lcm = m1 * (m2 // gcd)
            x = (a1 * (m2 // gcd) * mod_inverse(m2 // gcd, m1) + a2 * (m1 // gcd) * mod_inverse(m1 // gcd, m2)) % lcm
            return x, lcm
        a, m = information[0]
        for a2, m2 in information[1:]:
            a, m = combine(a, m, a2, m2)
        return a, m
    residue, modulo = crt(information)
    
    log.info(f"d mod {modulo} = {residue}")

    # d = q * modulo + residue
    # (q * modulo + residue) * G = Q
    
    q = bsgs(E.add(Q, E.mul(-residue, Generator)), E.mul(modulo, Generator), (target - residue) // modulo + 1)
    d = q * modulo + residue

    io.sendlineafter(b"Now do you trust me? OwO", b"y")

    for _ in range(10):
        io.recvuntil(b"C1: ")
        C1 = deserialize_point(io.recvline().strip().decode())
        io.recvuntil(b"C2: ")
        C2 = deserialize_point(io.recvline().strip().decode())
        io.sendlineafter(b"Secret: ", str(E.add(C2, E.mul(-d, C1))).encode())
    
    print(io.recvall())