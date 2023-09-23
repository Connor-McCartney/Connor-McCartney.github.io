---
permalink: /cryptography/rsa/Refactor-ASIS-quals-2023
title: Refactor - ASIS quals 2023
---

<br>

[Challenge Files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2023/ASIS-quals/Refactor)

<br>
<br>

First find a multiple of phi and use that to factor n.

<br>

Then since e**2 divides phi we have to solve it like [this challenge](https://hackmd.io/fmdfFQ2iS6yoVpbR3KCiqQ?view#cryptobaby-rsa).

<br>

Also since we have a larger e and sage's nth_root function sucks I used a pari call instead. 


<br>
<br>

```python
from Crypto.Util.number import long_to_bytes
from tqdm import tqdm
import random

def factor_with_kphi(n, kphi):
    t = 0
    while kphi % 2 == 0:
        kphi >>= 1
        t += 1
    for i in range(1, 101):
        g = random.randint(0, n) 
        y = pow(g, kphi, n)
        if y == 1 or y == n - 1:
            continue
        else:
            for j in range(1, t): 
                x = pow(y, 2, n)
                if x == 1:
                    p = gcd(n, y-1)
                    q = n//p
                    return p, q
                elif x == n - 1:
                    continue
                y = x
                x = pow(y, 2, n)
                if x == 1:
                    p = gcd(n, y-1)
                    q = n//p
                    return p, q

def mod_nth_root(x, e, n):
    r, z = pari(f"r = sqrtn(Mod({x}, {n}), {e}, &z); [lift(r), lift(z)]")
    r, z = int(r), int(z)
    roots = [r]
    t = r
    while (t := (t*z) % n) != r:
        roots.append(t)
    return roots

n = 15354257069173285781905276045639014609593379926482050489113547339117588412057832262093892509606681500550900795674355198875730897090963848584014735402479257641196755288572505568604616504895577156519599359709585689487167929035277328860394887100644352498762646576634768748203691626550604902474991908656069443025123380468043304218262437495617397923826383876725820263637369772201236276175774820781740263113457945850397866995318921153304724846886489062447149970082086628646772837892015556355384776002878980523779509899708723447721484662031731419684247739500573264103203416815345858413217500504527510275599764791910780108801
c = 11319719392368830772976523857976369154729855326260479489071566552409492905894844561614086707874832191432242950123964961582894044688274348653418226595519872495639236324552876924940961325755770656445013054487327399663358245181836741250528901918846037855858412978924591011941242779828600098063462814300900861180897010043498668688944295535981632815932395145673684660722012731208682402231321184600968865557231738026003707732466182970622224802483189066444000715061144732475930157185474148162121034705457395021374353689284243509307079898846581316271587575615363632603786729853488699442091342820074301120194843407072588515822
e = 31337

kphi = e**2
for i in range(1, 110):
    for j in range(1, 313):
        kphi *= i**2 + 31337 * j**2

q, p = factor_with_kphi(n, kphi)
p_roots = mod_nth_root(c, e, p) 
q_roots = mod_nth_root(c, e, q) 

def solve():
    for xp in tqdm(p_roots[6150:]):
        for xq in q_roots:
            x = crt([xp, xq], [p,q])
            flag = long_to_bytes(int(x))
            try:
                return flag.decode()
            except:
                continue

print(solve())
```

<br>

UPDATE

Since the flag was less than p and q you could solve it way faster:

```python
q, p = factor_with_kphi(n, kphi)

for flag in mod_nth_root(c%p, e, p):
    try:
        print(long_to_bytes(int(flag)).decode())
    except:
        continue
```
