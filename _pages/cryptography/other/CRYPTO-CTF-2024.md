---
permalink: /cryptography/other/CRYPTO-CTF-2024
title: CRYPTO CTF 2024
---

<br>
<br>

[Challenge Files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2024/CRYPTO%20CTF)

<br>

# Alibos

```python
	c = (pkey + d ** 2 * m) % (10 ** d)
```

Rearranging for m:

```python
from Crypto.Util.number import *

pkey = 8582435512564229286688465405009040056856016872134514945016805951785759509953023638490767572236748566493023965794194297026085882082781147026501124183913218900918532638964014591302221504335115379744625749001902791287122243760312557423006862735120339132655680911213722073949690947638446354528576541717311700749946777
enc  = 6314597738211377086770535291073179315279171595861180001679392971498929017818237394074266448467963648845725270238638741470530326527225591470945568628357663345362977083408459035746665948779559824189070193446347235731566688204757001867451307179564783577100125355658166518394135392082890798973020986161756145194380336

d = len(str(pkey))
m = ((enc-pkey) * pow(d**2, -1, 10**d)) % 10**d
print(m)
print(long_to_bytes(int(str(m)[:108])))

# 6170704326493336128242608193100736601774626903966803036318189045381903593682775829229200905376968543264526051111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
# CCTF{h0M3_m4De_cRyp70_5ySTeM_1N_CryptoCTF!!!}
```


# Beheaded

This was like the famous ECB penguin, you could rescale it in gimp or use a block where all pixels are the same colour without needing to find the key. 

# Mashy

Guessy trash, had to guess that sh was `a483b30944cbf762d4a3afc154aad825`. 

Then you can just send a bunch of md5 collisions, so that xor(h1, h2) is b'\x00\x00 ...'

# Ahoo

No source provided.

```
$ nc 00.cr.yp.toc.tf 17371
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Welcome to Ahoo task! Given integer n, find the smallest positive   ┃
┃ integer c such that n * c has the minimum number of 1 bits in its   ┃
┃ binary representation. Completing all steps will reveal the flag :) ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
┃ Please send the number of 1 bits in n * c and the integer c for
┃ n = 3823, separated by comma: 
```

Had to pass several rounds of this.

Check:

<https://arxiv.org/pdf/2002.02731>

<https://github.com/FinnLidbetter/sturdy-numbers>



# Soufia

(No source chall)

@ctfguy's Solution:

```python
from pwn import *

conn = remote('03.cr.yp.toc.tf', 13377)

def read_val(conn):
    for _ in range(4):
        print(conn.recvline().decode())

    s=conn.recvline().decode()
    print(s)
    y1 = int(s.split('=')[1].split(',')[0].strip())
    s=conn.recvline().decode()
    print(s)
    x2 = int(s.split('(')[1].split(')')[0])
    y2 = int(s.split('=')[1].split('┃')[0].strip())
    conn.recvline().decode()
    return int(0),int(x2),int(y1),int(y2)

def cal(val):
    a = (y2 - y1) // (x2 - x1)
    b = y1 - a * x1
    return (a * val) + b

x1,x2,y1,y2 = read_val(conn)
print(x1,x2,y1,y2)

s=conn.recvline().decode()
val = int(s.split('(')[1].split(')')[0])
ans=cal(val)
conn.sendline(str(ans).encode())
print(conn.recvline().decode())
def conti():
        s=conn.recvline().decode()
        print(s)
        val = int(s.split('(')[1].split(')')[0])
        ans=cal(val)
        conn.sendline(str(ans).encode())
        print(conn.recvline())

while True:
    conti()
```

```
[+] Opening connection to 03.cr.yp.toc.tf on port 13377: Done
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓

┃ .::   Soufia is a random oracle, your mission is to break it   ::. ┃

┃ We know that f: Z → Z and for all integers `x' and `y' we have:    ┃

┃     f(t * x) + t * f(y) = f(f(x + y)) for constant integer `t'.    ┃

┃ Also, f(0) = 209907020941535864741588746126965728575,              ┃

┃ and   f(91) = 1369168415328908069957513174528303837593             ┃

0 91 209907020941535864741588746126965728575 1369168415328908069957513174528303837593
┃ Good job, try the next step 2

┃ Please send the f(45):

b'\xe2\x94\x83 Good job, try the next step 3\n'
┃ Please send the f(32):

b'\xe2\x94\x83 Good job, try the next step 4\n'
┃ Please send the f(155):

b'\xe2\x94\x83 Good job, try the next step 5\n'
┃ Please send the f(356):

...

b'\xe2\x94\x83 Good job, try the next step 18\n'
┃ Please send the f(3910397):

b'\xe2\x94\x83 Good job, try the next step 19\n'
┃ Please send the f(2008442):

b'\xe2\x94\x83 Good job, try the next step 20\n'
┃ Please send the f(14329881):

b"\xe2\x94\x83 Congratz! You got the flag: b'CCTF{A_funCti0nal_3qu4tiOn_iZ_4_7yPe_oF_EquAtioN_tHaT_inv0lVe5_an_unKnOwn_funCt!on_r4tH3r_thAn_juS7_vArIabl3s!!}'\n"
```

# Solmaz

```python
px, py = (1338, 9218578132576071095213927906233283616907115389852794510465118810355739314264)
qx, qy = (3454561753909947353764378180794889923919743476068813953002808647958908878895, 17267599534808803050751150297274989016063324917454246976792837120400888025519)
A = qx*(py^2-px^3) - px*(qy^2-qx^3)
p = 30126567747372029007183424263223733382328264316268541293679065617875255137317
assert A%p == 0

c = (py^2 - px^3) * pow(px, -1, p) % p
E = EllipticCurve(GF(p), [c, 0])
P = E(px, py)
Q = E(qx, qy)
m = Q.log(P)
print(bytes.fromhex(f'{m:02x}'))
# 3cC_d1ViSibil!7Y
```
