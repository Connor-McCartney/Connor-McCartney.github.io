---
permalink: /cryptography/rsa/one-step-closer-HTB-cyber-apocalypse-CTF-2022 
title: One Step Closer - HTB Cyber Apocalypse CTF 2022 
---

<br>

# Challenge

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime, inverse
import random

FLAG = b'HTB{--REDACTED--}'
p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 257


def encrypt_flag():
    a = random.getrandbits(1024)
    b = random.getrandbits(1024)

    flag = bytes_to_long(FLAG)

    msg = a*flag + b

    ct = pow(msg, e, n)
    return {'ct': format(ct, 'x'), 'n': format(n, 'x'), 'e': format(e, 'x'), 'a': format(a, 'x'), 'b': format(b, 'x')}
```

<br>

The same flag (m) is encrypted with the same keys but random affine padding:

$$c_1$$ = $$(a_1 \cdot m + b_1)^e mod \ n$$
$$c_2$$ = $$(a_2 \cdot m + b_2)^e mod \ n$$


```python
from Crypto.Util.number import *

n = 0x8ce418b20a329eeefd82dd3e2b3c6ff3413737bd8902b145a895ffc1fca377acfcc013897c068917b50ab96a27f2f59c4a8363df1e5e568770dc2e1c819d8f6a0196e5158a403d1ef9e20c9c63d2235fbbcb55ba324c00e249e9bfafac29e04548e186bdfad56a2050dea14359d260fd621f19b5a7716f5f7f29f4aa988d8d388a2a75a50575166fbed64938297810186642005f0f60932eae0a6c17d9789943abd90afc1a21d0b80cecea9db9f75eb7caa4e05675839ab8fba9022bc2e03520e84cadf55ddbeb84c228d7e6850657b37c805a71690d2ece34ea91182f4311cd43ced2f38a49a96c7c1a7cd3c1a47851e5e533a6d04b105e62862119077d7199
e = 0x101
c1 = 0x4ad6b11011a3c69ec68aefdb452bc9462e9d6c32581a897d5620b16e9c84abc354752e2fb5fb346cab40a98c599ea4eb48fcd9e7ccb62d763423a70d3ed3153a5022bf35c14bd256b7be0ec0a0d6d0648a23918ae92fabc15e9285d4c6b24ae09feb1029b5eef13c5e7e9c03a30934b5a63069b99e0029a13750682bb7468fea9adb1646066fb4b145a2163e4a7048efdc28143ce8660bf1855ccb75d6f0a478651f32b1429bf87486ebf23e8aff855c6b40075ab2e5261aff6d877ca08b647a9b8bbc58234e9207b512f4be2729b104aa89a8a70425213d52c24609b1ffa6494f15fad74159e7fe8f2ff9253e90563c7059828b298a0ffc44f6edf7d2d2ef64
a1 = 0x991b8c7f8d417876621f40e0a0415e33c64c987a7d7a48585265b2c5e1b07b9d8a0e8edb8ecaf20b3bbbbd3301678ea4f52fedbfdcc5f6cc6b31352bc40327992abb836bf6519f2e495dff1dc7dd2c863bb2780d5c5ebe5fc3300c92975cd0f62dbbe01a517a81e031142ae5f655095550ac1fb70fd34e2caebd800af228e500
b1 = 0x2c1eec0b9dc6ff109597400b853a9f7218822efc76eebcbc19259b6a703fb1faf96b126bebee557372de0e1133c1ff140e2e8c07c3d33b8655f13634ba717e47a12bf66f3a346d0c202516786d05ff3ff238f7ee7e8a274280c55d70b10776e609c2e8c37eede14be7a4f73da06781bd46be7bc2ae67cb000557f1041ea0ea7a
c2 = 0x2f63ff6790277ce9e2736073448785ea43d6182fa363ca490bfdd6f6060ec9cdb305139057d0c892f51cc449fff281a2b82205195060e7880f5bbdd270a36cf45dd116b12797da2facc5ec29fd4fd4790a6c8a42b32bf8a3b6cc7097a5c319ef6f175b28e657daa34520a3293c57abef6681dc10c7df4cf3ee46559f383fa584ff32535202d68f78d2d964543f8b4215a6c22fdd3cd6c8c3fe2d41aded023aebec04867a1ba06d53dc71c48ba2c9bd7f5d3b935835d7c47661a5f1d5be3679c4de42bca318d18d433f113e613be44de7726be66b6d8a315b138d5d2cc8c1f2fdc20e3a1b4d47dba6eac27808c97c0891d6a71368d5b313ec74addbb74c1842d3
a2 = 0xb3a2eacbf051016ccc932dc1294597c081f6dd0be2427728612c50767733315dde904593955ade102534d1fd50961dd12f69fa64236720f6afb367f2319b1164be8d1ffa8818d2e23c9cb66245d1e04ea81be45491451cc021be9def6c36560ce526a847767f6ba63b7c703d2e7007db985e62b1705635beca1815d4dbe4a9eb
b2 = 0xef1dad6a52744c557d3e10bf08117f7b7f22678757c9f67ef4adad0c2b8d9575800f7b9dcb1a96d5e1dccf4a4c670727089904e697e7f1051811c79ff49248912001b0e87537447de27603c864dc3aa0b4865c45882dc0f9c7a53552cf15b54bb7717067bed040c19b8425890da100c9a9dd8e9b1d1dc2950837d3fc78d4c15a

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a.monic()

def FranklinReiter(c1, c2, e, n, a1, b1, a2, b2):
    P.<X> = PolynomialRing(Zmod(n))
    g1 = (a1*X + b1)^e - c1
    g2 = (a2*X + b2)^e - c2
    return int(-gcd(g1, g2).coefficients()[0])

m = FranklinReiter(c1, c2, e, n, a1, b1, a2, b2)
print(long_to_bytes(m))
#HTB{f1n1t3_d1ff3r3nc35_134d_70_r31473d_m355493_4774ck5}
```
