---
permalink: /cryptography/other/Nostalgic-SECCONCTF14
title: Nostalgic - SECCON CTF 14 (2025)
---

<br>
<br>


Challenge:

```python
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import os


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


FLAG = os.getenv("FLAG", "flag{dummy}")

key = get_random_bytes(32)
nonce = get_random_bytes(12)
SPECIAL_MIND = get_random_bytes(16)

print(f"my SPECIAL_MIND is {SPECIAL_MIND.hex()}")


def enc(plaintext=None):
    if plaintext == None:
        plaintext = get_random_bytes(15)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return ct, tag


special_rain = get_random_bytes(16)
special_ct, special_tag = enc(plaintext=special_rain)

print(f"special_rain_enc = {special_ct.hex()}")
print(f"special_rain_tag = {special_tag.hex()}")

while True:

    if (inp := input("what is your mind: ")) != "need":
        if enc(plaintext=xor(special_rain, bytes.fromhex(inp)))[1] == SPECIAL_MIND:
            print(f"I feel the same!!.. The flag is {FLAG}")
        else:
            print("No... not the same...")
        break
    else:
        print(f"my MIND was {enc(plaintext=None)[1].hex()}")
```


---

<br>

<br>

<br>


Solve:

Well don't let the ChaCha trick you into thinking this is about stream cipher shenanigans, it's more mathematical. 


This was the first chall I've tried that deals with Poly1305, so I had lots of research to do, here's a dump:

<https://l3ak.team/2024/04/21/plaid24/>

<https://zenn.dev/kurenaif/articles/2a005936de308a>

<https://github.com/tl2cents/AEAD-Nonce-Reuse-Attacks>

<https://github.com/kalmarunionenctf/kalmarctf/tree/main/2024/crypto/PolyCG1305>

<https://datatracker.ietf.org/doc/html/rfc7539>

<https://github.com/ph4r05/py-chacha20poly1305/blob/master/chacha20poly1305/poly1305.py>

<https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/Cipher/ChaCha20.py#L244>

<https://github.com/Legrandin/pycryptodome/blob/master/src/poly1305.c>


---

Well first I learned what the 1305 means:

```py
sage: p = 2**130 - 5
sage: is_prime(p)
True
```


<br>



Now to look at the chall, if we just keep sending 'need', we can collect infinite sample of `print(f"my MIND was {enc(plaintext=None)[1].hex()}")`

That is, we have access to as many 16-byte MAC tags as we like.

Now I needed to learn how these MAC tags are created. 

<https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/Cipher/ChaCha20.py#L244>

Here we see r and s are derived from the key and nonce. The key and nonce are static in the chall, so r and s are both static too!

r and s come from 16 bytes, so they are both <2**128. Also note everything seems to use little endian. 


In Crypto/Cipher/ChaCha20_Poly1305.py we see how the ciphertext is modified:

```py
    def _compute_mac(self):
        """Finalize the cipher (if not done already) and return the MAC."""

        if self._mac_tag:
            assert(self._status == _CipherStatus.PROCESSING_DONE)
            return self._mac_tag

        assert(self._status != _CipherStatus.PROCESSING_DONE)

        if self._status == _CipherStatus.PROCESSING_AUTH_DATA:
            self._pad_aad()

        if self._len_ct & 0x0F:
            self._authenticator.update(b'\x00' * (16 - (self._len_ct & 0x0F)))

        self._status = _CipherStatus.PROCESSING_DONE

        self._authenticator.update(long_to_bytes(self._len_aad, 8)[::-1])
        self._authenticator.update(long_to_bytes(self._len_ct, 8)[::-1])
        self._mac_tag = self._authenticator.digest()
        return self._mac_tag
```

We have no aad (additional associated data) in this chall so that is ignored. 

<br>

From [this writeup](https://l3ak.team/2024/04/21/plaid24/) we see the input is usually `AD || pad(AD) || C || pad(C) || len(AD) || len(C)` but `C || pad(C) || len(AD) || len(C)` with no aad. 

As a one-liner, 

```python
msg = ct + b'\x00' * ((16 - len(ct) % 16) % 16) + (0).to_bytes(8,'little') + len(ct).to_bytes(8,'little')
```


<br>

<br>



Next we delve into the [c code](https://github.com/Legrandin/pycryptodome/blob/master/src/poly1305.c)

Note the poly1305_load_r function, it clamps r. 

Finally, [this python implementation](https://github.com/tl2cents/AEAD-Nonce-Reuse-Attacks/blob/main/chacha-poly1305/chacha_poly1305_forgery.py) was very helpful, I just had to edit r and s. 

Note the mod 2**128 at the end because the tag is truncated to 16 bytes. 

So now we can make a test script for how the MAC tag is created:

```py
from os import urandom
from Crypto.Cipher import ChaCha20_Poly1305

plaintext = urandom(15)
key = urandom(32)
nonce = urandom(12)

cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
ct, tag = cipher.encrypt_and_digest(plaintext)

print(tag.hex()) # can we reproduce this?
```


<br>

<br>

And successfully reproduce it:

```py
from os import urandom
from Crypto.Cipher import ChaCha20_Poly1305, ChaCha20

plaintext = urandom(15)
key = urandom(32)
nonce = urandom(12)

cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
ct, tag = cipher.encrypt_and_digest(plaintext)

print(tag.hex()) # can we reproduce this?




# reproduce r, s
rs = ChaCha20.new(key=key, nonce=nonce).encrypt(b'\x00'*32)
r, s = rs[:16], rs[16:]
r, s = int.from_bytes(r, 'little'), int.from_bytes(s, 'little')

def poly1305_mac(r, s, msg):
    p = 2**130 - 5 
    r &= 0x0ffffffc0ffffffc0ffffffc0fffffff # clamped
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i+16] + b'\x01'
        block = int.from_bytes(block, 'little')
        acc = (acc + block) * r % p
    acc += s
    acc = int(acc % 2**128)
    return acc.to_bytes(16, 'little') 

msg = ct + b'\x00' * ((16 - len(ct) % 16) % 16) + (0).to_bytes(8,'little') + len(ct).to_bytes(8,'little')
reproduced_tag = poly1305_mac(r, s, msg)
print(reproduced_tag.hex())
assert tag == reproduced_tag
```



<br>

<br>


In this challenge, the ciphertexts are always the same size and the for loop that does the accumulation only loops twice, so let's simplify it:


```python
from os import urandom
from Crypto.Cipher import ChaCha20_Poly1305, ChaCha20

plaintext = urandom(15)
key = urandom(32)
nonce = urandom(12)

cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
ct, tag = cipher.encrypt_and_digest(plaintext)
t = int.from_bytes(tag, 'little')


# reproduce r, s
rs = ChaCha20.new(key=key, nonce=nonce).encrypt(b'\x00'*32)
r, s = rs[:16], rs[16:]
r, s = int.from_bytes(r, 'little'), int.from_bytes(s, 'little')




p = 2**130 - 5 
m = 2**128
r &= 0x0ffffffc0ffffffc0ffffffc0fffffff # clamped
x = int.from_bytes(ct, 'little') # unknown
b = int.from_bytes((0).to_bytes(8,'little') + len(ct).to_bytes(8,'little') + b'\x01', 'little') # known, msg[16:32]
assert t == ((((256**16+x)*r**2 + b*r) % p) + s) % m

# unknowns:
assert r<2**124 # a bit less than 128 bc of clamping
assert s<2**128 
assert x<2**120
```


<br>

<br>



Alright now we've escaped the crypto stuff and it's just math equations to solve. 


$$t_i = ((((256^{16} + x_i) \cdot r^2 + b \cdot r) \pmod p) + s) \pmod m$$


Can get rid of the mods, introduce some new vars k_i and j_i:


$$t_i = 256^{16} \cdot r^2 + x_i \cdot r^2 + b \cdot r + k_i \cdot p + s + j_i \cdot m$$


`256^16 * r^2 + br + s` is constant, if we subtract pairs of equations we can eliminate it:

$$t_{i+1} - t_i = (x_{i+1} - x_i) \cdot r^2 + (k_{i+1} - k_i) \cdot p + (j_{i+1} - j_i) \cdot m$$


<br>


Now just some notation cleanup:


$$tt_i = t_{i+1} - t_i$$

$$xx_i = x_{i+1} - x_i$$

$$kk_i = k_{i+1} - k_i$$

$$jj_i = j_{i+1} - j_i$$

$$R = r^2$$

$$tt_i = xx_i \cdot R + jj_i \cdot m + kk_i \cdot p$$

<br>

And as a reminder, 

knowns: `tt_i. m, p`

unknowns: `xx_i, jj_i, kk_i, R`



Let's start another test script:


```python
p = 2**130 - 5 
m = 2**128

while True:
    r = randint(0, 2**124)
    s = randint(0, 2**128)
    R = r**2


    xx_2 = randint(0, 2**120)
    xx_1 = randint(0, 2**120)
    xx_i = xx_2 - xx_1

    tt_2 = ((xx_2*R) % p) % m
    tt_1 = ((xx_1*R) % p) % m

    jj_2 = (tt_2 - ((xx_2*R) % p)) // m
    jj_1 = (tt_1 - ((xx_1*R) % p)) // m

    jj_i = jj_2 - jj_1  
    tt_i = tt_2 - tt_1

    assert -3 <= jj_i <= 3 
    #print(jj_i)
    assert tt_i % p == (xx_i*R + jj_i*m) % p
```


<br>

So we see jj_i is in a very small range. Now we switch the equation back to mod p and begin dealing with orthogonal lattice techniques. 


$$tt_i = xx_i \cdot R + jj_i \cdot m \pmod p$$


The first thing we want to solve is jj_i:




```python
def find_ortho_mod(mod, *vecs):
    assert len(set(len(v) for v in vecs)) == 1, "vectors have different lengths"
    base = [[matrix(vecs).T, matrix.identity(len(vecs[0]))]]
    if mod is not None:
        base += [[ZZ(mod), 0]]
    L = block_matrix(ZZ, base)
    nv = len(vecs)
    L[:, :nv] *= mod 
    L = L.LLL()
    ret = []
    for row in L:
        if row[:nv] == 0:
            ret.append(row[nv:])
    return matrix(ret)

p = 2**130 - 5 
m = 2**128

r = randint(0, 2**124)
s = randint(0, 2**128)
R = r**2
print(f'{R = }')

N = 100
xx = []
tt = []
jj = []
for _ in range(N):
    xx_2 = randint(0, 2**120)
    xx_1 = randint(0, 2**120)
    xx_i = xx_2 - xx_1
    xx.append(xx_i)

    tt_2 = ((xx_2*R) % p) % m
    tt_1 = ((xx_1*R) % p) % m
    tt_i = tt_2 - tt_1
    tt.append(tt_i)

    jj_2 = (tt_2 - ((xx_2*R) % p)) // m
    jj_1 = (tt_1 - ((xx_1*R) % p)) // m
    jj_i = jj_2 - jj_1  
    jj.append(jj_i)

print(f'{jj = }')




orth1 = find_ortho_mod(p, tt).BKZ()[:-2]
for o in orth1: 
    assert o * vector(GF(p), tt) == 0

    # tt_i = xx_i * R + jj_i*m (mod p)
    # when we find vectors orthogonal to tt_i, they also happen to be orthogonal to xx_i and jj_i (hopefully)
    assert o * vector(GF(p), xx) == 0
    assert o * vector(GF(p), jj) == 0


orth2 = find_ortho_mod(p, *orth1)
for o in orth2:
    assert o * vector(GF(p), orth1[0]) == 0
    assert o * vector(GF(p), orth1[1]) == 0
    assert o * vector(GF(p), orth1[2]) == 0
    ...

print('solved jj (maybe negative):', orth2[0])
```

Nice it worked, we found some orth1 orthogonal to jj_i and xx_i, then jj_i (the shortest) appeared in orth2. 



Now we can use another lattice to solve for xx_i. 


$$tt_i = xx_i \cdot R + jj_i \cdot m \pmod p$$


$$tt_i - jj_i \cdot m \equiv xx_i \cdot R \pmod p$$

Here `tt_i - jj_i * m` is just a constant now, but there is still 2 unknowns multiplied on the right hand side which is a little annoying. 

But we can easily just divide out the R:

$$R^-1 \cdot (tt_i - jj_i \cdot m) \equiv xx_i \pmod p$$

