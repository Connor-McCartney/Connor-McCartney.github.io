---
permalink: /cryptography/ecc/manykey-IrisCTF-2024
title: manykey - IrisCTF 2024
---

<br>

Challenge:

```python
from ecdsa import SigningKey
import secrets
sk = SigningKey.generate()
pk = sk.verifying_key

message = secrets.token_bytes(16)
print("Hello,", message.hex())
sig = sk.sign(message)
print(sig.hex())

print("Here's my public key")
print(pk.to_der().hex())

print("What was my private key again? (send me DER-encoded hex bytes)")
der = bytes.fromhex(input(""))

sk2 = SigningKey.from_der(der)
vk2 = sk2.verifying_key

assert sk2.privkey.secret_multiplier * sk2.curve.generator == vk2.pubkey.point
assert vk2.verify(sig, message)

with open("flag") as f:
    flag = f.read()
    print(flag, sk2.sign(flag.encode()))
```

<br>

Solve:

<br>


First let's check out a random verifying key:

```python
>>> from ecdsa import SigningKey  
>>> sk = SigningKey.generate()  
>>> pk = sk.verifying_key  
>>> pk  
VerifyingKey.from_string(b'\x02\x93\x90\xb5\xb2)\x99  
\xd0\xe0\xebN\x19K\x03\xc91B\x16\xb2<r\x89\xf1\x12\t  
', NIST192p, sha1)
```

<br>

We see the default curve is NIST192p and default hash function is sha1. 

We can google paramaters for NIST192p: <https://neuromancer.sk/std/nist/P-192>

Then we have to send a der encoding in which we can control the 
secret exponent (I'll refer to as d) and a chosen generator (I'll refer to as CG).

Here is the code used to verify a signature: <https://github.com/tlsfuzzer/python-ecdsa/blob/master/src/ecdsa/ecdsa.py#L184>

You may refer to this too: <https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm>


$$(\frac{h}{s} \cdot CG + \frac{r}{s} \cdot Q).x \equiv r \ \text{(mod n)}$$

Where `Q = d*CG`


$$(\frac{h}{s} \cdot CG + \frac{r}{s} \cdot d \cdot CG).x \equiv r \ \text{(mod n)}$$

Equivalently, (since `r = (k*G).x mod n`), (Note: the previous G, not our new chosen CG)

$$(\frac{h}{s} \cdot CG + \frac{r}{s} \cdot d \cdot CG) = kG$$

Then since ecc scalar multiplication distributes over addition, we can factor out CG:


$$CG(\frac{h + r\cdot d}{s}) = kG$$

Now let's let `CG = t * kG` for some t:

$$kG \cdot t(\frac{h + r\cdot d}{s}) = kG$$

$$t  \equiv \frac{s}{h+r\cdot d} \text{ (mod n)}$$

We know that kG = (r, lift_x(r)), so now we can choose any d, calculate the corresponding t and CG, then send it :)

```python
from pwn import remote
from hashlib import sha1
from ecdsa import SigningKey, ellipticcurve, curves
from sympy import sqrt_mod

def lift_x(x, a, b, p):
    return sqrt_mod(x**3 + a*x + b, p)

io = remote("manykey.chal.irisc.tf", "10102")
io.readline()
msg = bytes.fromhex(io.readline().decode().split()[-1])
h = int(sha1(msg).hexdigest(), 16)

sig = io.readline().decode()
r = int(sig[:48], 16)
s = int(sig[48:], 16)
io.read()

def attack(h, r, s):
    # NIST192p params
    p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
    a = 0xfffffffffffffffffffffffffffffffefffffffffffffffc
    b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
    n = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831
    curve = ellipticcurve.CurveFp(p, a, b)

    kG = ellipticcurve.PointJacobi(curve, x=r, y=lift_x(r, a, b, p), z=1, order=n)
    d = 42069 # choose whatever privkey your heart desires
    t = (s * pow(h+r*d, -1, n)) % n
    CG = t*kG
    mycurve = curves.Curve(curve=curve, generator=CG, oid=None, name="my curve xD")
    return SigningKey.from_secret_exponent(secexp=d, curve=mycurve).to_der().hex()

der = attack(h, r, s)
io.sendline(der.encode())
print(io.readline().decode())

# irisctf{key_generating_machine}
```
