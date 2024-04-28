---
permalink: /cryptography/rsa/Key-Recovery-UMD-CTF-2024
title: Key Recovery - UMD CTF 2024
---

(5 solves)

<br>
<br>

[Challenge Files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2024/UMD%20CTF/Key%20Recovery)

<br>

So, this is our corrupted RSA private key we need to fix:

```
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCW5dDBVxDUCBNa
Ij3Pb1WotuEevhrG57FA/U1pjRFb7T+uF53FT4PebJgmSVF8jREhWH4dn//7TK
tMdIS+zMhZO9aN/Gi3z+kOfDBky7uB+7u7J+6MWsHc/o7EiQ/dG0bHaekXfC
fBJaq9KRsKbPyCnqepsO8JC2RRAh2PPlUuLBoCcK8MPz+mw5j+ovD7vgzh
ht0m1Kqc4sDlyjiYq6ZG/Y0PqTO4zvBTnDFN4YH+1wUZwEytW1zURG/X
mgMvnSomUMuiOpAAlXXXZRFYp1pkEbzhSdUYseCTXkdwlsAT0x2+aT
Gt6vgzoJAgMBAAECggEAB7FcqwnYxXtJ6hQjAyj0yX6iGHKho9bn
wZjaBfEC7IgSjUHuO3bOBkPgKuHfmq/ZRWOLlOx5L7rcztDpA5
yK4N45/TUzrldBIqGulnU2O2/AHqt8nDEgYdKDrO2xDFJR4N
yiLMjkj9ldMC6dRKBrRvZ0xn9E6626W9s0eU+gVhBkKgJQ
Nhp36voGmWqzyci+ykQ4qZamuESesY+IaOdUh3fsrI9v
9Hdgq8eqDI27izDzyVLkQ5zIYgAsrVRiiXubUsE2Rw
HP3OtUc/NeLFnC7LRQhOxZOxhGV29PZ7IXyxPm4a
+4o0pr11U76BHLLs6HnARpwESmPn+CSzT3ybQB
zVkABlLRmC518wyXWOTp4XCLjwKBgQC+FTnA
1UUX6ktxlmuuTAuuuWQye5dgIQJPMAqN6Z
cTijylwEh6gMxibBtiSND55cC8LGcjRc
uutrHn/05wKBgQCa34sqtAcmn1U2K6
03ZLPOB7b74ndmBqbccbkYXljoxe
PKAhUEHI2WRxnS4nxB+K7CWuKX
iAZccEl7Ns2ZolJJdHvIS0jq
QVf8w481PGHUyidYeEghOS
EYHhHiSvzFTPNUfV/KJX
XYoMIrOjuTPL4R0ldm
KtuMdViZR2BcFITn
X/D8vi4h5+Xk2/
-----END PRI
```

<br>

First I filled it with some /'s, then when it's converted to hex the long sequences of f's stand out as our unknown segments. 

```
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCW5dDBVxDUCBNa
Ij3Pb1WotuEevhrG57FA/U1pjRFb7T+uF53FT4PebJgmSVF8jREhWH4dn//7TK//
tMdIS+zMhZO9aN/Gi3z+kOfDBky7uB+7u7J+6MWsHc/o7EiQ/dG0bHaekXfC////
fBJaq9KRsKbPyCnqepsO8JC2RRAh2PPlUuLBoCcK8MPz+mw5j+ovD7vgzh//////
ht0m1Kqc4sDlyjiYq6ZG/Y0PqTO4zvBTnDFN4YH+1wUZwEytW1zURG/X////////
mgMvnSomUMuiOpAAlXXXZRFYp1pkEbzhSdUYseCTXkdwlsAT0x2+aT//////////
Gt6vgzoJAgMBAAECggEAB7FcqwnYxXtJ6hQjAyj0yX6iGHKho9bn////////////
wZjaBfEC7IgSjUHuO3bOBkPgKuHfmq/ZRWOLlOx5L7rcztDpA5//////////////
yK4N45/TUzrldBIqGulnU2O2/AHqt8nDEgYdKDrO2xDFJR4N////////////////
yiLMjkj9ldMC6dRKBrRvZ0xn9E6626W9s0eU+gVhBkKgJQ//////////////////
Nhp36voGmWqzyci+ykQ4qZamuESesY+IaOdUh3fsrI9v////////////////////
9Hdgq8eqDI27izDzyVLkQ5zIYgAsrVRiiXubUsE2Rw//////////////////////
HP3OtUc/NeLFnC7LRQhOxZOxhGV29PZ7IXyxPm4a////////////////////////
+4o0pr11U76BHLLs6HnARpwESmPn+CSzT3ybQB//////////////////////////
zVkABlLRmC518wyXWOTp4XCLjwKBgQC+FTnA////////////////////////////
1UUX6ktxlmuuTAuuuWQye5dgIQJPMAqN6Z//////////////////////////////
cTijylwEh6gMxibBtiSND55cC8LGcjRc////////////////////////////////
uutrHn/05wKBgQCa34sqtAcmn1U2K6//////////////////////////////////
03ZLPOB7b74ndmBqbccbkYXljoxe////////////////////////////////////
PKAhUEHI2WRxnS4nxB+K7CWuKX//////////////////////////////////////
iAZccEl7Ns2ZolJJdHvIS0jq////////////////////////////////////////
QVf8w481PGHUyidYeEghOS//////////////////////////////////////////
EYHhHiSvzFTPNUfV/KJX////////////////////////////////////////////
XYoMIrOjuTPL4R0ldm//////////////////////////////////////////////
KtuMdViZR2BcFITn////////////////////////////////////////////////
X/D8vi4h5+Xk2///////////////////////////////////////////////////
```

<br>

Now standard PEM analysis, looking for headers/values.

I have headers in green, the redacted parts in red, n in cyan, e in yellow, d in orange, p in pink and q in purple. 

I ignored dp, dq, and iq because they seemed too redacted to be any use. 

<tt>308204be020100300d06092a864886f70d0101010500048204a8308204a4020100<span style="color:green">**028201<br>
01**</span><span style="color:cyan">0096e5d0c15710d408135a223dcf6f55a8b6e11ebe1ac6e7b140fd4d698d115bed3fae<br>
179dc54f83de6c982649517c8d1121587e1d9<span style="color:red">ffff</span>b4cafffb4c7484beccc8593bd68dfc6<br>
8b7cfe90e7c3064cbbb81fbbbbb27ee8c5ac1dcfe8ec4890fdd1b46c769e9177c2<span style="color:red">ffffff</span><br>
7c125aabd291b0a6cfc829ea7a9b0ef090b6451021d8f3e552e2c1a0270af0c3f3fa6c39<br>
8fea2f0fbbe0ce1<span style="color:red">fffffffff</span>86dd26d4aa9ce2c0e5ca3898aba646fd8d0fa933b8cef053<br>
9c314de181fed70519c04cad5b5cd4446fd7<span style="color:red">ffffffffffff</span>9a032f9d2a2650cba23a9000<br>
9575d7651158a75a6411bce149d518b1e0935e477096c013d31dbe693<span style="color:red">fffffffffffffff</span><br>
1adeaf833a09</span><span style="color:green">**0203**</span><span style="color:yellow">010001</span><span style="color:green">**02820100**</span><span style="color:orange">07b15cab09d8c57b49ea14230328f4c97ea21872a1<br>
a3d6e7<span style="color:red">ffffffffffffffffff</span>c198da05f102ec88128d41ee3b76ce0643e02ae1df9aafd9<br>
45638b94ec792fbadcced0e9039<span style="color:red">fffffffffffffffffffff</span>c8ae0de39fd3533ae574122a<br>
1ae9675363b6fc01eab7c9c312061d283acedb10c5251e0d<span style="color:red">ffffffffffffffffffffffff</span><br>
ca22cc8e48fd95d302e9d44a06b46f674c67f44ebadba5bdb34794fa05610642a0250<span style="color:red">fff<br>
ffffffffffffffffffffffff</span>361a77eafa06996ab3c9c8beca4438a996a6b8449eb18f88<br>
68e7548777ecac8f6<span style="color:red">ffffffffffffffffffffffffffffffff</span>47760abc7aa0c8dbb8b30f3<br>
c952e4439cc862002cad5462897b9b52c13647</span><span style="color:green">**028181**</span><span style="color:fuchsia">00<span style="color:red">ffffffffffffffffffffffffff</span><br>
1cfdceb5473f35e2c59c2ecb45084ec593b1846576f4f67b217cb13e6e1a<span style="color:red">ffffffffffff<br>
fffffffffffffffffffffffff</span>b8a34a6bd7553be811cb2ece879c0469c044a63e7f824b3<br>
4f7c9b401<span style="color:red">fffffffffffffffffffffffffffffffffffffff</span>cd59000652d1982e75f30c97<br>
58e4e9e1708b8f</span><span style="color:green">**028181**</span><span style="color:darkorchid">00be1539c0<span style="color:red">ffffffffffffffffffffffffffffffffffffffffff</span><br>
d54517ea4b71966bae4c0baeb964327b976021024f300a8de99<span style="color:red">fffffffffffffffffffff<br>
ffffffffffffffffffffffff</span>7138a3ca5c0487a80cc626c1b6248d0f9e5c0bc2c672345c<br>
<span style="color:red">ffffffffffffffffffffffffffffffffffffffffffffffff</span>baeb6b1e7ff4e7</span><span style="color:green">**028181**</span>009a<br>
df8b2ab407269f55362bafffffffffffffffffffffffffffffffffffffffffffffffffff<br>
d3764b3ce07b6fbe2776606a6dc71b9185e58e8c5effffffffffffffffffffffffffffff<br>
ffffffffffffffffffffffff3ca0215041c8d964719d2e27c41f8aec25ae297fffffffff<br>
ffffffffffffffffffffffffffffffffffffffffffffffff88065c70497b36cd99a25249<br>
747bc84b48eaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff<br>
4157fcc38f353c61d4ca2758784821392fffffffffffffffffffffffffffffffffffffff<br>
ffffffffffffffffffffffff1181e11e24afcc54cf3547d5fca257ffffffffffffffffff<br>
ffffffffffffffffffffffffffffffffffffffffffffffff5d8a0c22b3a3b933cbe11d25<br>
766fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff<br>
2adb8c75589947605c1484e7ffffffffffffffffffffffffffffffffffffffffffffffff<br>
ffffffffffffffffffffffff5ff0fcbe2e21e7e5e4dbffffffffffffffffffffffffffff<br>
ffffffffffffffffffffffffffffffffffffffffffffffff</tt><br>

<br>

Ok what's next...

The usual attempts of Coppersmith or BFS fail because there are chunks of n missing.  

So I turned to another equation:

$$0 \equiv 1 - e \cdot d \text{ (mod phi)}$$

$$\text{phi} = \text{lcm(p-1, q-1)} =  \frac{(p-1) \cdot (q-1)}{2 \cdot z} \text{ , for some small } z$$


$$0 = (1 - e \cdot d) + k \cdot \frac{(p-1) \cdot (q-1)}{2 \cdot z} \text{ , for some } k \lt e$$

$$0 = 2 \cdot z \cdot (1 - e \cdot d) + k \cdot (p-1) \cdot (q-1)$$

$$0 = 2 \cdot z \cdot (1 - e \cdot d) + k \cdot (n - p - q + 1)$$

Multiply by p (or q works too, WLOG):

$$0 = 2 \cdot z \cdot p \cdot (1 - e \cdot d) + k \cdot (n \cdot p - p^2 - n + p)$$


This is our magic equation we can reuse over and over to solve missing chunks of either n, d, p or q.

We'll work from the LSB towards the MSB.

For the first one we have to brute k and z, for the rest it should be the same. 

You can solve the equations with solve_mod in sage, or I chose 2-acidic because it's faster.  

<br>

# Initial values

```
n = 0x0096e5d0c15710d408135a223dcf6f55a8b6e11ebe1ac6e7b140fd4d698d115bed3fae179dc54f83de6c982649517c8d1121587e1d9ffffb4cafffb4c7484beccc8593bd68dfc68b7cfe90e7c3064cbbb81fbbbbb27ee8c5ac1dcfe8ec4890fdd1b46c769e9177c2ffffff7c125aabd291b0a6cfc829ea7a9b0ef090b6451021d8f3e552e2c1a0270af0c3f3fa6c398fea2f0fbbe0ce1fffffffff86dd26d4aa9ce2c0e5ca3898aba646fd8d0fa933b8cef0539c314de181fed70519c04cad5b5cd4446fd7ffffffffffff9a032f9d2a2650cba23a90009575d7651158a75a6411bce149d518b1e0935e477096c013d31dbe693fffffffffffffff1adeaf833a09
d =    0x7b15cab09d8c57b49ea14230328f4c97ea21872a1a3d6e7ffffffffffffffffffc198da05f102ec88128d41ee3b76ce0643e02ae1df9aafd945638b94ec792fbadcced0e9039fffffffffffffffffffffc8ae0de39fd3533ae574122a1ae9675363b6fc01eab7c9c312061d283acedb10c5251e0dffffffffffffffffffffffffca22cc8e48fd95d302e9d44a06b46f674c67f44ebadba5bdb34794fa05610642a0250fffffffffffffffffffffffffff361a77eafa06996ab3c9c8beca4438a996a6b8449eb18f8868e7548777ecac8f6ffffffffffffffffffffffffffffffff47760abc7aa0c8dbb8b30f3c952e4439cc862002cad5462897b9b52c13647
p =                                                                                                                                                                                                                                                                 0x00ffffffffffffffffffffffffff1cfdceb5473f35e2c59c2ecb45084ec593b1846576f4f67b217cb13e6e1afffffffffffffffffffffffffffffffffffffb8a34a6bd7553be811cb2ece879c0469c044a63e7f824b34f7c9b401fffffffffffffffffffffffffffffffffffffffcd59000652d1982e75f30c9758e4e9e1708b8f
q =                                                                                                                                                                                                                                                                 0x00be1539c0ffffffffffffffffffffffffffffffffffffffffffd54517ea4b71966bae4c0baeb964327b976021024f300a8de99fffffffffffffffffffffffffffffffffffffffffffff7138a3ca5c0487a80cc626c1b6248d0f9e5c0bc2c672345cffffffffffffffffffffffffffffffffffffffffffffffffbaeb6b1e7ff4e7
```

<br>

# Chunk 1

We can use d_low and p_low to solve n_low.

```
n = ...e693fffffffffffffff1adeaf833a09
d = ...39cc862002cad5462897b9b52c13647
p = ...652d1982e75f30c9758e4e9e1708b8f
```

```py
from tqdm import trange

e = 65537
n = 0x0096e5d0c15710d408135a223dcf6f55a8b6e11ebe1ac6e7b140fd4d698d115bed3fae179dc54f83de6c982649517c8d1121587e1d9ffffb4cafffb4c7484beccc8593bd68dfc68b7cfe90e7c3064cbbb81fbbbbb27ee8c5ac1dcfe8ec4890fdd1b46c769e9177c2ffffff7c125aabd291b0a6cfc829ea7a9b0ef090b6451021d8f3e552e2c1a0270af0c3f3fa6c398fea2f0fbbe0ce1fffffffff86dd26d4aa9ce2c0e5ca3898aba646fd8d0fa933b8cef0539c314de181fed70519c04cad5b5cd4446fd7ffffffffffff9a032f9d2a2650cba23a90009575d7651158a75a6411bce149d518b1e0935e477096c013d31dbe693fffffffffffffff1adeaf833a09
d =    0x7b15cab09d8c57b49ea14230328f4c97ea21872a1a3d6e7ffffffffffffffffffc198da05f102ec88128d41ee3b76ce0643e02ae1df9aafd945638b94ec792fbadcced0e9039fffffffffffffffffffffc8ae0de39fd3533ae574122a1ae9675363b6fc01eab7c9c312061d283acedb10c5251e0dffffffffffffffffffffffffca22cc8e48fd95d302e9d44a06b46f674c67f44ebadba5bdb34794fa05610642a0250fffffffffffffffffffffffffff361a77eafa06996ab3c9c8beca4438a996a6b8449eb18f8868e7548777ecac8f6ffffffffffffffffffffffffffffffff47760abc7aa0c8dbb8b30f3c952e4439cc862002cad5462897b9b52c13647
p =                                                                                                                                                                                                                                                                 0x00ffffffffffffffffffffffffff1cfdceb5473f35e2c59c2ecb45084ec593b1846576f4f67b217cb13e6e1afffffffffffffffffffffffffffffffffffffb8a34a6bd7553be811cb2ece879c0469c044a63e7f824b34f7c9b401fffffffffffffffffffffffffffffffffffffffcd59000652d1982e75f30c9758e4e9e1708b8f

PR.<n> = PolynomialRing(Zp(2, 4*32))
for z in range(1, 100):
    for k in trange(e):
        f = 2*z*p*(1-e*d) + k*(n*p - p**2 - n + p) 
        for n_low in [Integer(i) for i, _ in f.roots()]:
            n_low = f"{n_low:x}"
            if n_low[-6:] == "833a09":
                print(f"{n_low = }")
                print(f"{k = }")
                print(f"{z = }")
```

Leave that running for a while and it eventually finds:

```
n_low = '3e6932b4f5ddbbd6d5e41adeaf833a09'
k = 33411
z = 5
```

So replace 

`n = ...e693fffffffffffffff1ade...`

with 

`n = ...e6932b4f5ddbbd6d5e41ade...`

<br>

# Chunk 2

We can use n and d to solve a chunk of q.

```
n = ...149d518b1e0935e477096c013d31dbe6932b4f5ddbbd6d5e41adeaf833a09
d = ...47760abc7aa0c8dbb8b30f3c952e4439cc862002cad5462897b9b52c13647
q = ...fffffffffffffffffffffffffffffffffffffffffffffffbaeb6b1e7ff4e7
```

```python
k = 33411
z = 5
e = 65537
n = 0x0096e5d0c15710d408135a223dcf6f55a8b6e11ebe1ac6e7b140fd4d698d115bed3fae179dc54f83de6c982649517c8d1121587e1d9ffffb4cafffb4c7484beccc8593bd68dfc68b7cfe90e7c3064cbbb81fbbbbb27ee8c5ac1dcfe8ec4890fdd1b46c769e9177c2ffffff7c125aabd291b0a6cfc829ea7a9b0ef090b6451021d8f3e552e2c1a0270af0c3f3fa6c398fea2f0fbbe0ce1fffffffff86dd26d4aa9ce2c0e5ca3898aba646fd8d0fa933b8cef0539c314de181fed70519c04cad5b5cd4446fd7ffffffffffff9a032f9d2a2650cba23a90009575d7651158a75a6411bce149d518b1e0935e477096c013d31dbe6932b4f5ddbbd6d5e41adeaf833a09
d =    0x7b15cab09d8c57b49ea14230328f4c97ea21872a1a3d6e7ffffffffffffffffffc198da05f102ec88128d41ee3b76ce0643e02ae1df9aafd945638b94ec792fbadcced0e9039fffffffffffffffffffffc8ae0de39fd3533ae574122a1ae9675363b6fc01eab7c9c312061d283acedb10c5251e0dffffffffffffffffffffffffca22cc8e48fd95d302e9d44a06b46f674c67f44ebadba5bdb34794fa05610642a0250fffffffffffffffffffffffffff361a77eafa06996ab3c9c8beca4438a996a6b8449eb18f8868e7548777ecac8f6ffffffffffffffffffffffffffffffff47760abc7aa0c8dbb8b30f3c952e4439cc862002cad5462897b9b52c13647

var("q")
f = 2*z*q*(1-e*d) + k*(n*q - q**2 - n + q)
for q in solve_mod(f, 16**61)[:2]:
    print(f"{int(q[0]):x}")
```

Still 1 unknown byte at the top of that chunk of q, which we'll have to brute in the next step:

`q = ...345c??e1bfecce74ca8bc4cda299dd9770a76354a5ba4e0a093ebaeb6b1e7ff4e7`

<br>

# Chunk 3

We can use n and q to solve a chunk of d.

```
n = ...650cba23a90009575d7651158a75a6411bce149d518b1e0935e477096c013d31dbe6932b4f5ddbbd6d5e41adeaf833a09
d = ...c8f6ffffffffffffffffffffffffffffffff47760abc7aa0c8dbb8b30f3c952e4439cc862002cad5462897b9b52c13647
q = ...7a80cc626c1b6248d0f9e5c0bc2c672345c??e1bfecce74ca8bc4cda299dd9770a76354a5ba4e0a093ebaeb6b1e7ff4e7
```

```python
from tqdm import trange

k = 33411
z = 5
e = 65537
n = 0x0096e5d0c15710d408135a223dcf6f55a8b6e11ebe1ac6e7b140fd4d698d115bed3fae179dc54f83de6c982649517c8d1121587e1d9ffffb4cafffb4c7484beccc8593bd68dfc68b7cfe90e7c3064cbbb81fbbbbb27ee8c5ac1dcfe8ec4890fdd1b46c769e9177c2ffffff7c125aabd291b0a6cfc829ea7a9b0ef090b6451021d8f3e552e2c1a0270af0c3f3fa6c398fea2f0fbbe0ce1fffffffff86dd26d4aa9ce2c0e5ca3898aba646fd8d0fa933b8cef0539c314de181fed70519c04cad5b5cd4446fd7ffffffffffff9a032f9d2a2650cba23a90009575d7651158a75a6411bce149d518b1e0935e477096c013d31dbe6932b4f5ddbbd6d5e41adeaf833a09

var("d")

q_ = 0x7a80cc626c1b6248d0f9e5c0bc2c672345c00e1bfecce74ca8bc4cda299dd9770a76354a5ba4e0a093ebaeb6b1e7ff4e7
for b in trange(0xff):
    q = b*16**60 + q_
    f = 2*z*q*(1-e*d) + k*(n*q - q**2 - n + q)
    for dd in solve_mod(f, 16**97):
        dd = f"{int(dd[0]):x}"
        if "c8f6" in dd:
            print(f"{dd = }")
```

So replace 

`d = ...c8f6ffffffffffffffffffffffffffffffff4776...`

with

`d = ...c8f6f132321917e478b93c82e25e7fc3576f4776...`

<br>

# Chunk 4

We can use n and d to solve a chunk of p.

```
n = ...5d7651158a75a6411bce149d518b1e0935e477096c013d31dbe6932b4f5ddbbd6d5e41adeaf833a09
d = ...78b93c82e25e7fc3576f47760abc7aa0c8dbb8b30f3c952e4439cc862002cad5462897b9b52c13647
p = ...b401fffffffffffffffffffffffffffffffffffffffcd59000652d1982e75f30c9758e4e9e1708b8f
```

```python
k = 33411
z = 5
e = 65537
n = 0x0096e5d0c15710d408135a223dcf6f55a8b6e11ebe1ac6e7b140fd4d698d115bed3fae179dc54f83de6c982649517c8d1121587e1d9ffffb4cafffb4c7484beccc8593bd68dfc68b7cfe90e7c3064cbbb81fbbbbb27ee8c5ac1dcfe8ec4890fdd1b46c769e9177c2ffffff7c125aabd291b0a6cfc829ea7a9b0ef090b6451021d8f3e552e2c1a0270af0c3f3fa6c398fea2f0fbbe0ce1fffffffff86dd26d4aa9ce2c0e5ca3898aba646fd8d0fa933b8cef0539c314de181fed70519c04cad5b5cd4446fd7ffffffffffff9a032f9d2a2650cba23a90009575d7651158a75a6411bce149d518b1e0935e477096c013d31dbe6932b4f5ddbbd6d5e41adeaf833a09
d =    0x7b15cab09d8c57b49ea14230328f4c97ea21872a1a3d6e7ffffffffffffffffffc198da05f102ec88128d41ee3b76ce0643e02ae1df9aafd945638b94ec792fbadcced0e9039fffffffffffffffffffffc8ae0de39fd3533ae574122a1ae9675363b6fc01eab7c9c312061d283acedb10c5251e0dffffffffffffffffffffffffca22cc8e48fd95d302e9d44a06b46f674c67f44ebadba5bdb34794fa05610642a0250fffffffffffffffffffffffffff361a77eafa06996ab3c9c8beca4438a996a6b8449eb18f8868e7548777ecac8f6f132321917e478b93c82e25e7fc3576f47760abc7aa0c8dbb8b30f3c952e4439cc862002cad5462897b9b52c13647

var("p")
f = 2*z*p*(1-e*d) + k*(n*p - p**2 - n + p)
for p in solve_mod(f, 16**82)[:2]:
    print(f"{int(p[0]):x}")
```

So replace 

`p = ...b401fffffffffffffffffffffffffffffffffffffffcd59...`

with

`p = ...b401baf468eacceab2f20a31ddf08c97fb238e2f4b7cd59...`

<br>

# Chunk 5

We can use p and d to solve a chunk of n.

```
n = ...6fd7ffffffffffff9a032f9d2a2650cba23a90009575d7651158a75a6411bce149d518b1e0935e477096c013d31dbe6932b4f5ddbbd6d5e41adeaf833a09
d = ...a6b8449eb18f8868e7548777ecac8f6f132321917e478b93c82e25e7fc3576f47760abc7aa0c8dbb8b30f3c952e4439cc862002cad5462897b9b52c13647
p = ...7553be811cb2ece879c0469c044a63e7f824b34f7c9b401baf468eacceab2f20a31ddf08c97fb238e2f4b7cd59000652d1982e75f30c9758e4e9e1708b8f

```

```python
k = 33411
z = 5
e = 65537
d =    0x7b15cab09d8c57b49ea14230328f4c97ea21872a1a3d6e7ffffffffffffffffffc198da05f102ec88128d41ee3b76ce0643e02ae1df9aafd945638b94ec792fbadcced0e9039fffffffffffffffffffffc8ae0de39fd3533ae574122a1ae9675363b6fc01eab7c9c312061d283acedb10c5251e0dffffffffffffffffffffffffca22cc8e48fd95d302e9d44a06b46f674c67f44ebadba5bdb34794fa05610642a0250fffffffffffffffffffffffffff361a77eafa06996ab3c9c8beca4438a996a6b8449eb18f8868e7548777ecac8f6f132321917e478b93c82e25e7fc3576f47760abc7aa0c8dbb8b30f3c952e4439cc862002cad5462897b9b52c13647
p =                                                                                                                                                                                                                                                                 0x00ffffffffffffffffffffffffff1cfdceb5473f35e2c59c2ecb45084ec593b1846576f4f67b217cb13e6e1afffffffffffffffffffffffffffffffffffffb8a34a6bd7553be811cb2ece879c0469c044a63e7f824b34f7c9b401baf468eacceab2f20a31ddf08c97fb238e2f4b7cd59000652d1982e75f30c9758e4e9e1708b8f

var("n")
f = 2*z*p*(1-e*d) + k*(n*p - p**2 - n + p)
for n in solve_mod(f, 16**125)[:2]:
    print(f"{int(n[0]):x}")
```

So replace 

`n = ...6fd7ffffffffffff9a03...`

with

`n = ...6fd72ba470e034f59a03...`

<br>

# Chunk 6

We can use n and d to solve a chunk of q.

```
n = ...539c314de181fed70519c04cad5b5cd4446fd72ba470e034f59a032f9d2a2650cba23a90009575d7651158a75a6411bce149d518b1e0935e477096c013d31dbe6932b4f5ddbbd6d5e41adeaf833a09
d = ...361a77eafa06996ab3c9c8beca4438a996a6b8449eb18f8868e7548777ecac8f6f132321917e478b93c82e25e7fc3576f47760abc7aa0c8dbb8b30f3c952e4439cc862002cad5462897b9b52c13647
q = ...e99fffffffffffffffffffffffffffffffffffffffffffff7138a3ca5c0487a80cc626c1b6248d0f9e5c0bc2c672345c9ce1bfecce74ca8bc4cda299dd9770a76354a5ba4e0a093ebaeb6b1e7ff4e7
```

```python
k = 33411
z = 5
e = 65537
n = 0x0096e5d0c15710d408135a223dcf6f55a8b6e11ebe1ac6e7b140fd4d698d115bed3fae179dc54f83de6c982649517c8d1121587e1d9ffffb4cafffb4c7484beccc8593bd68dfc68b7cfe90e7c3064cbbb81fbbbbb27ee8c5ac1dcfe8ec4890fdd1b46c769e9177c2ffffff7c125aabd291b0a6cfc829ea7a9b0ef090b6451021d8f3e552e2c1a0270af0c3f3fa6c398fea2f0fbbe0ce1fffffffff86dd26d4aa9ce2c0e5ca3898aba646fd8d0fa933b8cef0539c314de181fed70519c04cad5b5cd4446fd72ba470e034f59a032f9d2a2650cba23a90009575d7651158a75a6411bce149d518b1e0935e477096c013d31dbe6932b4f5ddbbd6d5e41adeaf833a09
d =    0x7b15cab09d8c57b49ea14230328f4c97ea21872a1a3d6e7ffffffffffffffffffc198da05f102ec88128d41ee3b76ce0643e02ae1df9aafd945638b94ec792fbadcced0e9039fffffffffffffffffffffc8ae0de39fd3533ae574122a1ae9675363b6fc01eab7c9c312061d283acedb10c5251e0dffffffffffffffffffffffffca22cc8e48fd95d302e9d44a06b46f674c67f44ebadba5bdb34794fa05610642a0250fffffffffffffffffffffffffff361a77eafa06996ab3c9c8beca4438a996a6b8449eb18f8868e7548777ecac8f6f132321917e478b93c82e25e7fc3576f47760abc7aa0c8dbb8b30f3c952e4439cc862002cad5462897b9b52c13647

var("q")
f = 2*z*q*(1-e*d) + k*(n*q - q**2 - n + q)
for q in solve_mod(f, 16**158)[:2]:
    print(f"{int(q[0]):x}")
```

So replace 

`q = ...99fffffffffffffffffffffffffffffffffffffffffffff7138a...`

with 

`q = ...9945780316171a79d5200c0d1fb59a4d756aa1ff1df03517138a...`

<br>

# Chunk 7

We can use n and q to solve a chunk of d.

```
n = ...0e5ca3898aba646fd8d0fa933b8cef0539c314de181fed70519c04cad5b5cd4446fd72ba470e034f59a032f9d2a2650cba23a90009575d7651158a75a6411bce149d518b1e0935e477096c013d31dbe6932b4f5ddbbd6d5e41adeaf833a09
d = ...0250fffffffffffffffffffffffffff361a77eafa06996ab3c9c8beca4438a996a6b8449eb18f8868e7548777ecac8f6f132321917e478b93c82e25e7fc3576f47760abc7aa0c8dbb8b30f3c952e4439cc862002cad5462897b9b52c13647
q = ...e4c0baeb964327b976021024f300a8de9945780316171a79d5200c0d1fb59a4d756aa1ff1df03517138a3ca5c0487a80cc626c1b6248d0f9e5c0bc2c672345c9ce1bfecce74ca8bc4cda299dd9770a76354a5ba4e0a093ebaeb6b1e7ff4e7
```

```python
k = 33411
z = 5
e = 65537
n = 0x0096e5d0c15710d408135a223dcf6f55a8b6e11ebe1ac6e7b140fd4d698d115bed3fae179dc54f83de6c982649517c8d1121587e1d9ffffb4cafffb4c7484beccc8593bd68dfc68b7cfe90e7c3064cbbb81fbbbbb27ee8c5ac1dcfe8ec4890fdd1b46c769e9177c2ffffff7c125aabd291b0a6cfc829ea7a9b0ef090b6451021d8f3e552e2c1a0270af0c3f3fa6c398fea2f0fbbe0ce1fffffffff86dd26d4aa9ce2c0e5ca3898aba646fd8d0fa933b8cef0539c314de181fed70519c04cad5b5cd4446fd72ba470e034f59a032f9d2a2650cba23a90009575d7651158a75a6411bce149d518b1e0935e477096c013d31dbe6932b4f5ddbbd6d5e41adeaf833a09
q = 0x00be1539c0ffffffffffffffffffffffffffffffffffffffffffd54517ea4b71966bae4c0baeb964327b976021024f300a8de9945780316171a79d5200c0d1fb59a4d756aa1ff1df03517138a3ca5c0487a80cc626c1b6248d0f9e5c0bc2c672345c9ce1bfecce74ca8bc4cda299dd9770a76354a5ba4e0a093ebaeb6b1e7ff4e7

var("d")
f = 2*z*q*(1-e*d) + k*(n*q - q**2 - n + q)
for d in solve_mod(f, 16**190)[:2]:
    print(f"{int(d[0]):x}")
```

So replace

`d = ...0250fffffffffffffffffffffffffff361a...`

with 

`d = ...02501bf2dd86de8e2805bca239ee6c1361a...`

<br>

# Chunk 8

We can use n and d to solve a chunk of p.

```
n = ...fd8d0fa933b8cef0539c314de181fed70519c04cad5b5cd4446fd72ba470e034f59a032f9d2a2650cba23a90009575d7651158a75a6411bce149d518b1e0935e477096c013d31dbe6932b4f5ddbbd6d5e41adeaf833a09
d = ...e2805bca239ee6c1361a77eafa06996ab3c9c8beca4438a996a6b8449eb18f8868e7548777ecac8f6f132321917e478b93c82e25e7fc3576f47760abc7aa0c8dbb8b30f3c952e4439cc862002cad5462897b9b52c13647
p = ...6e1afffffffffffffffffffffffffffffffffffffb8a34a6bd7553be811cb2ece879c0469c044a63e7f824b34f7c9b401baf468eacceab2f20a31ddf08c97fb238e2f4b7cd59000652d1982e75f30c9758e4e9e1708b8f
```

```python
k = 33411
z = 5
e = 65537
n = 0x0096e5d0c15710d408135a223dcf6f55a8b6e11ebe1ac6e7b140fd4d698d115bed3fae179dc54f83de6c982649517c8d1121587e1d9ffffb4cafffb4c7484beccc8593bd68dfc68b7cfe90e7c3064cbbb81fbbbbb27ee8c5ac1dcfe8ec4890fdd1b46c769e9177c2ffffff7c125aabd291b0a6cfc829ea7a9b0ef090b6451021d8f3e552e2c1a0270af0c3f3fa6c398fea2f0fbbe0ce1fffffffff86dd26d4aa9ce2c0e5ca3898aba646fd8d0fa933b8cef0539c314de181fed70519c04cad5b5cd4446fd72ba470e034f59a032f9d2a2650cba23a90009575d7651158a75a6411bce149d518b1e0935e477096c013d31dbe6932b4f5ddbbd6d5e41adeaf833a09
d =    0x7b15cab09d8c57b49ea14230328f4c97ea21872a1a3d6e7ffffffffffffffffffc198da05f102ec88128d41ee3b76ce0643e02ae1df9aafd945638b94ec792fbadcced0e9039fffffffffffffffffffffc8ae0de39fd3533ae574122a1ae9675363b6fc01eab7c9c312061d283acedb10c5251e0dffffffffffffffffffffffffca22cc8e48fd95d302e9d44a06b46f674c67f44ebadba5bdb34794fa05610642a02501bf2dd86de8e2805bca239ee6c1361a77eafa06996ab3c9c8beca4438a996a6b8449eb18f8868e7548777ecac8f6f132321917e478b93c82e25e7fc3576f47760abc7aa0c8dbb8b30f3c952e4439cc862002cad5462897b9b52c13647

var("p")
f = 2*z*p*(1-e*d) + k*(n*p - p**2 - n + p)
for p in solve_mod(f, 16**175)[:2]:
    print(f"{int(p[0]):x}")
```

So replace 

`p = ...6e1afffffffffffffffffffffffffffffffffffffb8a3...`

with 

`p = ...6e1a3eb4ca82af6d6f80c3f876611ff417a29f5ffb8a3...`

<br>

# Chunk 9

We can use p and d to solve a chunk of n.

```
n = ...0ce1fffffffff86dd26d4aa9ce2c0e5ca3898aba646fd8d0fa933b8cef0539c314de181fed70519c04cad5b5cd4446fd72ba470e034f59a032f9d2a2650cba23a90009575d7651158a75a6411bce149d518b1e0935e477096c013d31dbe6932b4f5ddbbd6d5e41adeaf833a09
d = ...44ebadba5bdb34794fa05610642a02501bf2dd86de8e2805bca239ee6c1361a77eafa06996ab3c9c8beca4438a996a6b8449eb18f8868e7548777ecac8f6f132321917e478b93c82e25e7fc3576f47760abc7aa0c8dbb8b30f3c952e4439cc862002cad5462897b9b52c13647
p = ...5e2c59c2ecb45084ec593b1846576f4f67b217cb13e6e1a3eb4ca82af6d6f80c3f876611ff417a29f5ffb8a34a6bd7553be811cb2ece879c0469c044a63e7f824b34f7c9b401baf468eacceab2f20a31ddf08c97fb238e2f4b7cd59000652d1982e75f30c9758e4e9e1708b8f
```

```python
k = 33411
z = 5
e = 65537
d =    0x7b15cab09d8c57b49ea14230328f4c97ea21872a1a3d6e7ffffffffffffffffffc198da05f102ec88128d41ee3b76ce0643e02ae1df9aafd945638b94ec792fbadcced0e9039fffffffffffffffffffffc8ae0de39fd3533ae574122a1ae9675363b6fc01eab7c9c312061d283acedb10c5251e0dffffffffffffffffffffffffca22cc8e48fd95d302e9d44a06b46f674c67f44ebadba5bdb34794fa05610642a02501bf2dd86de8e2805bca239ee6c1361a77eafa06996ab3c9c8beca4438a996a6b8449eb18f8868e7548777ecac8f6f132321917e478b93c82e25e7fc3576f47760abc7aa0c8dbb8b30f3c952e4439cc862002cad5462897b9b52c13647
p =                                                                                                                                                                                                                                                                 0x00ffffffffffffffffffffffffff1cfdceb5473f35e2c59c2ecb45084ec593b1846576f4f67b217cb13e6e1a3eb4ca82af6d6f80c3f876611ff417a29f5ffb8a34a6bd7553be811cb2ece879c0469c044a63e7f824b34f7c9b401baf468eacceab2f20a31ddf08c97fb238e2f4b7cd59000652d1982e75f30c9758e4e9e1708b8f

var("n")
f = 2*z*p*(1-e*d) + k*(n*p - p**2 - n + p)
for n in solve_mod(f, 16**218):
    print(f"{int(n[0]):x}")
```

So replace 

`n = ...0ce1fffffffff86dd...`

with 

`n = ...0ce10406888c786dd...`

<br>

# Chunk 10

We can use n and d to solve all of q and very-close-to-all of p.

```
n =  ...f3e552e2c1a0270af0c3f3fa6c398fea2f0fbbe0ce10406888c786dd26d4aa9ce2c0e5ca3898aba646fd8d0fa933b8cef0539c314de181fed70519c04cad5b5cd4446fd72ba470e034f59a032f9d2a2650cba23a90009575d7651158a75a6411bce149d518b1e0935e477096c013d31dbe6932b4f5ddbbd6d5e41adeaf833a09
d =  ...??ca22cc8e48fd95d302e9d44a06b46f674c67f44ebadba5bdb34794fa05610642a02501bf2dd86de8e2805bca239ee6c1361a77eafa06996ab3c9c8beca4438a996a6b8449eb18f8868e7548777ecac8f6f132321917e478b93c82e25e7fc3576f47760abc7aa0c8dbb8b30f3c952e4439cc862002cad5462897b9b52c13647
p =   0xffffffffffffffffffffffffff1cfdceb5473f35e2c59c2ecb45084ec593b1846576f4f67b217cb13e6e1a3eb4ca82af6d6f80c3f876611ff417a29f5ffb8a34a6bd7553be811cb2ece879c0469c044a63e7f824b34f7c9b401baf468eacceab2f20a31ddf08c97fb238e2f4b7cd59000652d1982e75f30c9758e4e9e1708b8f
q =   0xbe1539c0ffffffffffffffffffffffffffffffffffffffffffd54517ea4b71966bae4c0baeb964327b976021024f300a8de9945780316171a79d5200c0d1fb59a4d756aa1ff1df03517138a3ca5c0487a80cc626c1b6248d0f9e5c0bc2c672345c9ce1bfecce74ca8bc4cda299dd9770a76354a5ba4e0a093ebaeb6b1e7ff4e7
```

```python
k = 33411
z = 5
e = 65537
n = 0x0096e5d0c15710d408135a223dcf6f55a8b6e11ebe1ac6e7b140fd4d698d115bed3fae179dc54f83de6c982649517c8d1121587e1d9ffffb4cafffb4c7484beccc8593bd68dfc68b7cfe90e7c3064cbbb81fbbbbb27ee8c5ac1dcfe8ec4890fdd1b46c769e9177c2ffffff7c125aabd291b0a6cfc829ea7a9b0ef090b6451021d8f3e552e2c1a0270af0c3f3fa6c398fea2f0fbbe0ce10406888c786dd26d4aa9ce2c0e5ca3898aba646fd8d0fa933b8cef0539c314de181fed70519c04cad5b5cd4446fd72ba470e034f59a032f9d2a2650cba23a90009575d7651158a75a6411bce149d518b1e0935e477096c013d31dbe6932b4f5ddbbd6d5e41adeaf833a09
d =    0x7b15cab09d8c57b49ea14230328f4c97ea21872a1a3d6e7ffffffffffffffffffc198da05f102ec88128d41ee3b76ce0643e02ae1df9aafd945638b94ec792fbadcced0e9039fffffffffffffffffffffc8ae0de39fd3533ae574122a1ae9675363b6fc01eab7c9c312061d283acedb10c5251e0dffffffffffffffffffffffffca22cc8e48fd95d302e9d44a06b46f674c67f44ebadba5bdb34794fa05610642a02501bf2dd86de8e2805bca239ee6c1361a77eafa06996ab3c9c8beca4438a996a6b8449eb18f8868e7548777ecac8f6f132321917e478b93c82e25e7fc3576f47760abc7aa0c8dbb8b30f3c952e4439cc862002cad5462897b9b52c13647

var("p")
f = 2*z*p*(1-e*d) + k*(n*p - p**2 - n + p)
for p in solve_mod(f, 16**254)[:2]:
    print(f"{int(p[0]):x}")
```

Full q: 

```python
q = 0xbe1539c015b032cf0d26365b903ccb0371d44082d6f18c3c45d54517ea4b71966bae4c0baeb964327b976021024f300a8de9945780316171a79d5200c0d1fb59a4d756aa1ff1df03517138a3ca5c0487a80cc626c1b6248d0f9e5c0bc2c672345c9ce1bfecce74ca8bc4cda299dd9770a76354a5ba4e0a093ebaeb6b1e7ff4e7
```

p (the rest can be bruted easily): 

```
???9e3ec26251fbb16b4593d121cfdceb5473f35e2c59c2ecb45084ec593b1846576f4f67b217cb13e6e1a3eb4ca82af6d6f80c3f876611ff417a29f5ffb8a34a6bd7553be811cb2ece879c0469c044a63e7f824b34f7c9b401baf468eacceab2f20a31ddf08c97fb238e2f4b7cd59000652d1982e75f30c9758e4e9e1708b8f
```

<br>

# Flag

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from math import lcm

enc = open('out.txt', 'rb').read()
q = 0xbe1539c015b032cf0d26365b903ccb0371d44082d6f18c3c45d54517ea4b71966bae4c0baeb964327b976021024f300a8de9945780316171a79d5200c0d1fb59a4d756aa1ff1df03517138a3ca5c0487a80cc626c1b6248d0f9e5c0bc2c672345c9ce1bfecce74ca8bc4cda299dd9770a76354a5ba4e0a093ebaeb6b1e7ff4e7
p = 0xcb39e3ec26251fbb16b4593d121cfdceb5473f35e2c59c2ecb45084ec593b1846576f4f67b217cb13e6e1a3eb4ca82af6d6f80c3f876611ff417a29f5ffb8a34a6bd7553be811cb2ece879c0469c044a63e7f824b34f7c9b401baf468eacceab2f20a31ddf08c97fb238e2f4b7cd59000652d1982e75f30c9758e4e9e1708b8f
e = 65537
d = pow(e, -1, lcm(p-1, q-1))
n = p*q
flag = PKCS1_OAEP.new(RSA.construct([n, e, d])).decrypt(enc)
print(flag.decode())

# UMDCTF{impressive_recovery!_i_forgot_to_tell_you_this_but_the_private_key_ends_with_VATE KEY-----}
```
