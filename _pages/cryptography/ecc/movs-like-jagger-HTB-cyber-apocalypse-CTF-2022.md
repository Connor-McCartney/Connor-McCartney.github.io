---
permalink: /cryptography/ecc/movs-like-jagger-HTB-cyber-apocalypse-CTF-2022 
title: MOVs Like Jagger - HTB Cyber Apocalypse CTF 2022 
---

<br>

[Challenge files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2022/HTB-Cyber-Apocalypse/crypto_movs_like_jagger)


The challenge title hints at the [MOV attack](https://eprint.iacr.org/2018/307.pdf) which works on curves with a small embedding degree. <br>

First we can define our curve and calculate the embedding degree (k):

```python
# curve
a = -35
b = 98
p = 434252269029337012720086440207
E = EllipticCurve(GF(p), [a,b])

# generator
Gx = 16378704336066569231287640165
Gy = 377857010369614774097663166640
G = E(Gx, Gy)

# public keys
A = E(0x53aa256fca975b0e2fd527aac, 0x1d4f956ec8a4458cfda8dff15)
B = E(0x21cd699755718698a1963cd50, 0x21e48edd5538758b156ee9328)

# embedding degree
k = 1
while (p**k - 1) % E.order() != 0:
    k += 1
print(k) 
```

<br>

We get k = 2, small enough for the MOV attack to work. It transfers the discrete log from $$E(F_p)$$ to $$F_{p^2}^\times$$, which is much easier. <br>

```python
def MOV_attack(E, G, A, k):
    E2 = EllipticCurve(GF(p**k), [a,b])
    T = E2.random_point()
    M = T.order()
    N = G.order()
    d = gcd(M, N)
    T1 = (M//d) * T
    s1 = E2(G).weil_pairing(T1, N)
    s2 = E2(A).weil_pairing(T1, N)
    nA = s2.log(s1)
    return nA

nA = MOV_attack(E, G, A, k)
secret = nA * B
print(secret.xy()) # (338674607206389654805492721792, 390828491586972541331184235565)
```

The secret would be different depending on the public keys the server gives you. <br>
Submit to get flag HTB{I7_5h0075_,1t_m0v5,_wh47_15_i7?}. 
