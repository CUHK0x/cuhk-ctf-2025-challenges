START = 1000
INC = 576
END = 50625

# easy=cuhk25ctf{T%5GY}
# START = 8
# INC = 4
# END = 24

# Solution
from sympy import sieve

sieve.extend_to_no(END + 1)

primes: list[int] = [sieve._list[i - 1] for i in range(START, END + 1, INC)]  # type: ignore
answer = "cuhk25ctf{"
for i in primes:
    i %= 100
    while i <= 32:
        i += 5
        i = (i * i) % 100
    answer += chr(i)
answer += "}"

# answer=cuhk25ctf{L;)T%W)5,SC?`!)1``81ES1cS?+)TaETTEL+MEGL))M);COM@)$SQ=)=Q+SO+)GWa1G;]+a5,T3L])[=TL9E[8G}
print(f"{answer=}")


## Actual program translation
print("cuhk25ctf{", end="")
while True:
    curr = START
    p = 1
    while curr != 0:
        s = 2
        p += 1
        while p % s != 0:
            s += 1
        if s == p:
            curr -= 1
    while True:
        p %= 100
        if p > 32:
            break
        p += 5
        p *= p
    print(chr(p), end="")
    START += INC
    if START > END:
        print("}")
        break
