---
permalink: /cryptography/other/AlpacaHack2025
title: AlpacaHack 2025
---


<br>

# RSAMPC

```python
import os
from Crypto.Util.number import getRandomRange, getPrime, bytes_to_long

FLAG = os.environ.get("FLAG", "fakeflag").encode()

def additive_share(a):
    t0, t1 = getRandomRange(-2**512, 2**512), getRandomRange(-2**512, 2**512)
    t2 = a-t0-t1
    return t0, t1, t2

def replicated_share(a):
    t = additive_share(a)
    return [(t[i], t[(i+1)%3]) for i in range(3)]

def multiply_shares(sa, sb):
    def mul(t, u):
        return t[0]*u[0]+t[0]*u[1]+t[1]*u[0]
    r = additive_share(0)
    z = [mul(sa[i], sb[i])+r[i] for i in range(3)]
    w = [(z[i], z[(i+1)%3]) for i in range(3)]
    return w

def reconstruct(s):
    return s[0][0] + s[0][1] + s[1][1]

p = getPrime(512)
q = getPrime(512)

sp = replicated_share(p)
sq = replicated_share(q)
print("your share of p:", sp[0])
print("your share of q:", sq[0])

spq = multiply_shares(sp, sq)
print("your share of pq:", spq[0])

n = reconstruct(spq)
assert n == p*q
print("n:", n)

e = 0x10001
c = pow(bytes_to_long(FLAG + os.urandom(127-len(FLAG))), e, n)
print("e:", e)
print("c:", c)
```

```
  your share of p: (-384164070196680113629973964276599320736606300184523772854135294036334447818682200607218877531386512793858125339877828582394197679795576991953411880314517, 178776721087372919385257940734429604253240493277094581482580652949038337321961407291832241379559936948198042043881180916670462219794291885959730598632423)
  your share of q: (-10504102453855211730773548202462643334445368588122773952797120588540073173181223269420294976331168878842123082669069593895980908615299058089156709125348617, 3324659724832936014805633502878093035237335054058544453532695059432217891926271390882999445452501190449380595220556388508799059755133895886341486877191502)
  your share of pq: (880194945859095512548778390949753106113259354062743403885130575509194611686622871911550689148439940097472063798899034574466553154127726867674397008987477001207806315461004286936941315001029394217039765579529660629019466179402060549350587729722354909331590051509695082365313846996923469825646557408789955494, 40388351148875096689764230410867470980240794826105168292967479483809364773078955483003274901375600951153408618729650715655666480989756454152565386666760509805904377793675351489295406907138019316039841793386393194481700178651652081449097569147179108704523020190287922457859082133424057955783092523665228634328)
  n: 122269467950798077326822634108968850809243750508493781647505745002863843379348700424238562022365315227978807541070854658246091147872559714237246479088170538196473585543281713624525798244748333546435600544573727499127916535316599284592352755786055339638261774730837681190375466416924715653324305527245715836447
  e: 65537
  c: 100976267335628681910815317357700490412039872278731196009735781349258998302355802361980783540754919888894607253589239383351290237447746132667260747986281172840910605287343986031579879857474734142154881821962810929745626899955618676413832332521656625264015203959361696843594006345498340544121922011105950850715
```

<br>

Observe the additive_share function is called 3 times, creating 6 total unknowns which I'll call x0, x1, y0, y1, z0, z1.

And of course, p and q are also unknown. 

The reconstruction function also seems useless for us solvers. 

```python
def additive_share(a, t0, t1):
    #t0, t1 = getRandomRange(-2**512, 2**512), getRandomRange(-2**512, 2**512)
    t2 = a-t0-t1
    return t0, t1, t2

def replicated_share(a, t0, t1):
    t = additive_share(a, t0, t1)
    return [(t[i], t[(i+1)%3]) for i in range(3)]

def multiply_shares(sa, sb):
    def mul(t, u):
        return t[0]*u[0]+t[0]*u[1]+t[1]*u[0]
    r = additive_share(0, z0, z1)
    z = [mul(sa[i], sb[i])+r[i] for i in range(3)]
    w = [(z[i], z[(i+1)%3]) for i in range(3)]
    return w

var('p q')
var('x0 x1 y0 y1 z0 z1')

sp = replicated_share(p, x0, x1)
sq = replicated_share(q, y0, y1)
print("your share of p:", sp[0])
print("your share of q:", sq[0])

spq = multiply_shares(sp, sq)
print("your share of pq:", spq[0])
```

That just leaves us with this information

```
your share of p: (x0, x1)
your share of q: (y0, y1)
your share of pq: (x0*y0 + x1*y0 + x0*y1 + z0,    (q - y0 - y1)*x1 + (p - x0 - x1)*y1 + x1*y1 + z1)
```

We're given x0, x1, y0 and y1. We can also solve z0 easily from the first equation:

```python
assert z0 == spq[0][0] - (x0*y0 + x1*y0 + x0*y1 )
```

Then we're just left with the second equation. 

```
assert spq[0][1] == q*x1 - x1*y0 + p*y1 - x0*y1 - x1*y1 + z1
```

Multiply by p to get rid of q:

```python
assert p*spq[0][1] == n*x1 - p*x1*y0 + p**2 * y1 - p*x0*y1 - p*x1*y1 + z1*p
```

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>


# addprimes


```python
import os
import signal
from sage.misc.banner import require_version
from Crypto.Util.number import getPrime, bytes_to_long

assert require_version(10), "This challenge requires SageMath version 10 or above"

signal.alarm(30)
FLAG = os.environ.get("FLAG", "Alpaca{*** FAKEFLAG ***}").encode()
assert FLAG.startswith(b"Alpaca{")

p = getPrime(512)
q = getPrime(512)
n = p * q
e = 37

print("n:", n)
print("e:", e)

c = int(input("ciphertext: "))
assert 1 < c < n-1
pari.addprimes(p)
m = mod(c, n).nth_root(e)
print("plaintext:", m)

padded_flag = FLAG + os.urandom(127-len(FLAG))
print("encrypted flag:", pow(bytes_to_long(padded_flag), e, n))
```


<br>

<br>

We choose some c, receive `mod(c, n).nth_root(e)`, and must use this to get p or q. 

<br>


My idea is choose c = x**e for some random x. 

Then there's a chance we receive some m such that m ≡ x mod p.

In that case, we can take p = gcd(m-x, n) :)

So I ran this for a while


```python
from os import environ
environ['TERM'] = 'konsole'
from pwn import remote
from math import gcd

def main():
    e = 37
    x = 2 # random
    c = x**e

    while True:
        io = remote('34.170.146.252', 20209)
        n = int(io.recvline().split()[-1])
        print(f'{n = }')
        io.recvline()

        io.sendline(str(c).encode())
        m = int(io.recvline().split()[-1])

        p = gcd(m-x, n)
        print(f'{p = }')
        print(1<p<n)
        ct = int(io.recvline().split()[-1])
        print(f'{ct = }')
        io.close()
        if 1<p<n:
            return

main()
```

and found: 

```
n = 114783708399698960108264738054025145565535931640960999123387272969093599238187181373730111997294459975870565267518303558948000404485473308361774135465316252509197324620785772722459158341889447987572103958648599953204583497777731923408413905249543515516308414354177122583425216386764347082254251512033916977109
p = 11449730474587971262122289098680230045722988528466053486814133748804539665648353523162475259451265043814468677887855417914321306551770172524009610111075847
ct = 8172678213140054371240953996928112834530795207936773004164588627685749400433771007465676410907652762068158858567560176952250679582262129011487575337588475342755491452494415526321332283145276807676165921618511466237798151055970302819981173222405864150917608363173174596196189642400056796077399966472137429900
```

and now just decrypting:

```python
from Crypto.Util.number import *
e = 37
pari.addprimes(p)
for flag in Zmod(n)(ct).nth_root(e, all=True):
    flag = long_to_bytes(int(flag))
    if b'Alpaca' in flag:
        print(flag)

# Alpaca{k3ym0on's_favori7e_73chn1que!_x.com/kymn_/status/1527738058744791042}
```


<br>

<br>

---

Author's writeup: <https://chocorusk.hatenablog.com/entry/2025/01/26/180123>
