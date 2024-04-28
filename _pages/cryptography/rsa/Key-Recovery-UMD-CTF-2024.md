---
permalink: /cryptography/rsa/Key-Recovery-UMD-CTF-2024
title: Key Recovery - UMD CTF 2024
---

<br>
<br>

[Challenge Files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2024/UMD%20CTF/Key%20Recovery)

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


<tt>308204be020100300d06092a864886f70d0101010500048204a8308204a4020100<span style="color:green">**028201<br>
01**</span><span style="color:cyan">0096e5d0c15710d408135a223dcf6f55a8b6e11ebe1ac6e7b140fd4d698d115bed3fae<br>
179dc54f83de6c982649517c8d1121587e1d9<span style="color:red">ffff</span>b4cafffb4c7484beccc8593bd68dfc6<br>
8b7cfe90e7c3064cbbb81fbbbbb27ee8c5ac1dcfe8ec4890fdd1b46c769e9177c2<span style="color:red">ffffff</span><br>
7c125aabd291b0a6cfc829ea7a9b0ef090b6451021d8f3e552e2c1a0270af0c3f3fa6c39<br>
8fea2f0fbbe0ce1<span style="color:red">fffffffff</span>86dd26d4aa9ce2c0e5ca3898aba646fd8d0fa933b8cef053<br>
9c314de181fed70519c04cad5b5cd4446fd7<span style="color:red">ffffffffffff</span>9a032f9d2a2650cba23a9000<br>
9575d7651158a75a6411bce149d518b1e0935e477096c013d31dbe693<span style="color:red">fffffffffffffff</span><br>
1adeaf833a09<span style="color:green">**0203**</span>010001<span style="color:green">**02820100**</span>07b15cab09d8c57b49ea14230328f4c97ea21872a1<br>
a3d6e7<span style="color:red">ffffffffffffffffff</span>c198da05f102ec88128d41ee3b76ce0643e02ae1df9aafd9<br>
45638b94ec792fbadcced0e9039<span style="color:red">fffffffffffffffffffff</span>c8ae0de39fd3533ae574122a<br>
1ae9675363b6fc01eab7c9c312061d283acedb10c5251e0d<span style="color:red">ffffffffffffffffffffffff</span><br>
ca22cc8e48fd95d302e9d44a06b46f674c67f44ebadba5bdb34794fa05610642a0250<span style="color:red">fff<br>
ffffffffffffffffffffffff</span>361a77eafa06996ab3c9c8beca4438a996a6b8449eb18f88<br>
68e7548777ecac8f6<span style="color:red">ffffffffffffffffffffffffffffffff</span>47760abc7aa0c8dbb8b30f3<br>
c952e4439cc862002cad5462897b9b52c136470<span style="color:red">fffffffffffffffffffffffffffffffff</span><br>
1cfdceb5473f35e2c59c2ecb45084ec593b1846576f4f67b217cb13e6e1a<span style="color:red">ffffffffffff<br>
fffffffffffffffffffffffff</span>b8a34a6bd7553be811cb2ece879c0469c044a63e7f824b3<br>
4f7c9b401<span style="color:red">fffffffffffffffffffffffffffffffffffffff</span>cd59000652d1982e75f30c97<br>
58e4e9e1708b8f<span style="color:green">**028181**</span>00be1539c0<span style="color:red">ffffffffffffffffffffffffffffffffffffffffff</span><br>
d54517ea4b71966bae4c0baeb964327b976021024f300a8de99<span style="color:red">fffffffffffffffffffff<br>
ffffffffffffffffffffffff</span>7138a3ca5c0487a80cc626c1b6248d0f9e5c0bc2c672345c<br>
<span style="color:red">ffffffffffffffffffffffffffffffffffffffffffffffff</span>baeb6b1e7ff4e7<span style="color:green">**028181**</span>009a<br>
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
ffffffffffffffffffffffffffffffffffffffffffffffff</span></tt><br>

