import re

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def is_infinity(self):
        return self.x is None and self.y is None

    def __eq__(self, other):
        if self.is_infinity() and other.is_infinity():
            return True
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        if self.is_infinity():
            return "Point(infinity)"
        return f"Point({self.x}, {self.y})"

    def __hash__(self):
        if self.is_infinity():
            return hash((None, None))
        return hash((self.x, self.y))

class Squiggle:
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p

    def normalize(self, P):
        if P.is_infinity():
            return P
        return Point(P.x % self.p, P.y % self.p)

    def add(self, P, Q):
        P = self.normalize(P)
        Q = self.normalize(Q)
        if P.is_infinity():
            return Q
        if Q.is_infinity():
            return P
        if P == self.negate(Q):
            return Point(None, None)
        
        if P == Q:
            t = (3 * P.x * P.x + self.a) * pow(P.y << 1, -1, self.p) % self.p
        else:
            t = (Q.y - P.y) * pow(Q.x - P.x, -1, self.p) % self.p

        x = (t * t - P.x - Q.x) % self.p
        y = ((P.x - x) * t - P.y) % self.p
        
        return Point(x, y)

    def negate(self, P):
        P = self.normalize(P)
        if P.is_infinity():
            return P
        return Point(P.x, -P.y % self.p)

    def mul(self, k, P):
        P = self.normalize(P)
        result = Point(None, None)
        current = P

        if k < 0:
            return self.mul(-k, self.negate(P))

        while k > 0:
            if k & 1:
                result = self.add(result, current)
            current = self.add(current, current)
            k >>= 1

        return result

def deserialize_point(s):
    if s == "Point(infinity)":
        return Point(None, None)
    else:
        pattern = r"Point\(\d+, \d+\)"
        match = re.match(pattern, s)
        if not match:
            raise ValueError(f"Invalid point format: {s}")
        arr = s[6:-1].split(", ")
        return Point(int(arr[0]), int(arr[1]))