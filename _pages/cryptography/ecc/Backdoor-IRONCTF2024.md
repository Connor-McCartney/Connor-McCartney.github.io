---
permalink: /cryptography/ecc/Backdoor-IRONCTF2024
title: Backdoor - IRON CTF 2024
---

<br>

Challenge:

```python
from curve_operations import Point,Curve    # Custom module
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes

class Dual_EC:

    def __init__(self):
        p = 229054522729978652250851640754582529779
        a = -75
        b = -250
        self.curve = Curve(p,a,b)
        self.P = Point(97396093570994028423863943496522860154 , 2113909984961319354502377744504238189)
        self.Q = Point(137281564215976890139225160114831726699 , 111983247632990631097104218169731744696)
        self.set_initial_state()

    def set_initial_state(self):
        self.state = ???SECRET🤫???

    def set_next_state(self):
        self.state = self.curve.scalar_multiply(self.P, self.state).x

    def gen_rand_num(self):
        rand_point = self.curve.scalar_multiply(self.Q, self.state)
        rand_num = rand_point.x
        self.set_next_state()
        return rand_num

def main():
    prng = Dual_EC()
    flag = b'flag{test}'
    print("My PRNG has passed International Standards!!!")
    print("Here is a Sample Random Number to prove it to you : ", prng.gen_rand_num())
    key = long_to_bytes((prng.gen_rand_num() << 128) + prng.gen_rand_num())
    iv = long_to_bytes(prng.gen_rand_num())
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_bytes = cipher.encrypt(pad(flag, AES.block_size))
    print('Encrypted bytes : ',encrypted_bytes)

if(__name__ == "__main__"):
    main()
```

```
My PRNG has passed International Standards!!!
Here is a Sample Random Number to prove it to you :  222485190245526863452994827085862802196
Encrypted bytes :  b'BI\xd5\xfd\x8e\x1e(s\xb3vUhy\x96Y\x8f\xceRr\x0c\xe6\xf0\x1a\x88x\xe2\xe9M#]\xad\x99H\x13+\x9e5\xfd\x9b \xe6\xf0\xe10w\x80q\x8d'
```


<br>

<br>

Solve:

The curve parameters make a singular curve with an elliptic node. 

We can follow this link <https://crypto.stackexchange.com/questions/61302/how-to-solve-this-ecdlp>

We use an isomorphism to transfer the ecdlp to a discrete log mod p.

The mapping function is:

$$
(x, y) \ \mapsto \ \frac{y + x\sqrt{c}}{y - x\sqrt{c}}
$$

<br>

The first point we're given equals Q times the initial state, so let's solve the initial state:

```python
p = 229054522729978652250851640754582529779
a = -75
b = -250

qx = 137281564215976890139225160114831726699
qy = 111983247632990631097104218169731744696

# given sample output
sx = 222485190245526863452994827085862802196
sy = GF(p)(sx^3 + a*sx + b).nth_root(2, all=True)[0] # try both

def node_log(p, a, b, qx, qy, sx, sy):
    PR.<x> = PolynomialRing(GF(p))
    f = x^3 + a*x + b
    double_root = [r for r, e in f.roots() if e==2][0]

    # shifts
    qx -= double_root
    sx -= double_root 
    f2 = f.subs(x=x+double_root)

    c = f2.factor()[0][0].coefficients()[0]
    sqrt_c = GF(p)(c).sqrt()

    def mapping(x, y, sqrt_c):
        return (y + x*sqrt_c) * pow(y - x*sqrt_c, -1, p)

    return mapping(sx, sy, sqrt_c).log(mapping(qx, qy, sqrt_c))

print(node_log(p, a, b, qx, qy, sx, sy))
# 90590397774805613256408291471381126558
```

<br>

<br>

Now that we have the initial state, re-run the PRNG to get the key and iv:

```python
from collections import namedtuple
from Crypto.Util.number import *
from Crypto.Cipher import AES

Point = namedtuple("Point", "x y")
O = 'Origin'
p = 229054522729978652250851640754582529779
a = -75 
b = -250 

def check_point(P):
    if P == O:
        return True
    else:
        return (P.y**2 - (P.x**3 + a*P.x + b)) % p == 0 and 0 <= P.x < p and 0 <= P.y < p

def point_inverse(P):
    if P == O:
        return P
    return Point(P.x, -P.y % p)

def point_addition(P, Q):
    if P == O:
        return Q
    elif Q == O:
        return P
    elif Q == point_inverse(P):
        return O
    else:
        if P == Q:
            lam = (3*P.x**2 + a)*inverse(2*P.y, p)
            lam %= p
        else:
            lam = (Q.y - P.y) * inverse((Q.x - P.x), p)
            lam %= p
    Rx = (lam**2 - P.x - Q.x) % p
    Ry = (lam*(P.x - Rx) - P.y) % p
    R = Point(Rx, Ry)
    assert check_point(R)
    return R

def mul(P, n):
    Q = P
    R = O
    while n > 0:
        if n % 2 == 1:
            R = point_addition(R, Q)
        Q = point_addition(Q, Q)
        n = n // 2
    assert check_point(R)
    return R.x


class Dual_EC:
    def __init__(self):
        self.P = Point(97396093570994028423863943496522860154 , 2113909984961319354502377744504238189)
        self.Q = Point(137281564215976890139225160114831726699 , 111983247632990631097104218169731744696)
        self.set_initial_state()

    def set_initial_state(self):
        self.state = 90590397774805613256408291471381126558 #???SECRET???

    def set_next_state(self):
        self.state = mul(self.P, self.state)

    def gen_rand_num(self):
        rand_num = mul(self.Q, self.state)
        self.set_next_state()
        return rand_num

prng = Dual_EC()
print("Here is a Sample Random Number to prove it to you : ", prng.gen_rand_num())
key = long_to_bytes((prng.gen_rand_num() << 128) + prng.gen_rand_num())
iv = long_to_bytes(prng.gen_rand_num())
cipher = AES.new(key, AES.MODE_CBC, iv)
enc = b'BI\xd5\xfd\x8e\x1e(s\xb3vUhy\x96Y\x8f\xceRr\x0c\xe6\xf0\x1a\x88x\xe2\xe9M#]\xad\x99H\x13+\x9e5\xfd\x9b \xe6\xf0\xe10w\x80q\x8d'
print(cipher.decrypt(enc))
# ironCTF{5h0uld_h4v3_1is7en3d_t0_d4v1d_a1r34dy}
```
