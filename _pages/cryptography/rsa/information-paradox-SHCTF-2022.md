---
permalink: /cryptography/rsa/information-paradox-SHCTF-2022
title: Information Paradox - Space Heroes CTF 2022
---


[Challenge Files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2022/Space-Heroes/Information%20Paradox)

I learnt a lot about ASN.1 syntax from this challenge! Two extracts of the private key are given. <br>
I actually only needed the second extract to solve this challenge. First I converted to hex:

```python
from base64 import b64decode
from Crypto.Util.number import *

extract = """
GDYGPNllyOAIOZUCggEBANNvIJO9Roh+p3+E05/Lt4KtR7GxO8oIrslq/j3dZhdp
MbW1EomJv45grjC5hdk7e4k2vZKWnQsA0S1hKHwoklNIsbFEfzVBtLazVEnPF1/C
DFuCoP1HpZ9gKnPhr0YkaInPyVDax8b41GdHl/D9gUh0xXr8k2UlV10Kt5cN9IrV
Irb1CmW0IZyJKEmQRjIpQ/0aCn7Ygw+8SeluVGihwO7BD4GvjqiOeI/uDosELldu
jATEKZiWtUeBXcBPfIDWNQ0kAB4I1SFR4gkLH0B3bQgmGG/7ZkMeAOoeOh2Rn30s
GCbF9KPcxsaX0PROhlc5wgVs7ppcSjp9s6MjPN4qdH0CggEAKGj7TG24BYnr6r9J
nqDQPJ1sv4TckYiyHPeN752qw3grLAO0pQQYATe9W/d4yI+0jCZ8m3OXYAbJSkkO
9bwHxsFFmpmhXPAo1EmJwSD6x5rIV2z+kUhROLe7qBvCbesDxj47Hb4p2jOP0yHP
RS2BcA1gJ18O56ge1xOqVW/IYrHKaG1MN4/FjeailMu7FvAdcAF6nCQD5rIyNI1/
A5KO+uRxQwtUA5eahx21XIQm/S31VlMGzM4aeW+huyeAAG8q0uB72hSus9GC0PUK
8K/r06EeQ2fYeltYEhRzP7lrHyAUTO4xiopGPFlqXbD/3olItMDI0tfj+X+cKnUg
7sTM5QKCAQEAv4GIIEjv+fG+BOJqS/JY5SPOLEQ7w2LZ7dXbMm22ar39KHg5shny
""".replace("\n","")

extract_hex = hex(bytes_to_long(b64decode(extract)))[2:]
print(extract_hex)
```

Next I searched that ASN.1 integer headers have the format 0282xxxx. <br>
(02 means integer data type, 82 means the following 2 bytes represent <br>
the size of the integer, and xxxx is the following 2 bytes.) <br>
More info [here](https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/). <br>
Note we don't find e in this, but it usually has a short encoding form, and it's header is just 02xx.


1836063cd965c8e0083995<span style="color:green">**02820101**</span><span style="color:yellow">00d36f2093bd46887ea77f84d39fcbb782ad47b1b1 <br>
3bca08aec96afe3ddd66176931b5b5128989bf8e60ae30b985d93b7b8936bd92969d0b00<br>
d12d61287c28925348b1b1447f3541b4b6b35449cf175fc20c5b82a0fd47a59f602a73e1<br>
af46246889cfc950dac7c6f8d4674797f0fd814874c57afc936525575d0ab7970df48ad5<br>
22b6f50a65b4219c8928499046322943fd1a0a7ed8830fbc49e96e5468a1c0eec10f81af<br>
8ea88e788fee0e8b042e576e8c04c4299896b547815dc04f7c80d6350d24001e08d52151<br>
e2090b1f40776d0826186ffb66431e00ea1e3a1d919f7d2c1826c5f4a3dcc6c697d0f44e<br>
865739c2056cee9a5c4a3a7db3a3233cde2a747d</span><span style="color:green">**02820101**</span><span style="color:orange">2868fb4c6db80589ebeabf49<br>
9ea0d03c9d6cbf84dc9188b21cf78def9daac3782b2c03b4a504180137bd5bf778c88fb4<br>
8c267c9b73976006c94a490ef5bc07c6c1459a99a15cf028d44989c120fac79ac8576cfe<br>
91485138b7bba81bc26deb03c63e3b1dbe29da338fd321cf452d81700d60275f0ee7a81e<br>
d713aa556fc862b1ca686d4c378fc58de6a294cbbb16f01d70017a9c2403e6b232348d7f<br>
03928efae471430b5403979a871db55c8426fd2df5565306ccce1a796fa1bb2780006f2a<br>
d2e07bda14aeb3d182d0f50af0afebd3a11e4367d87a5b581214733fb96b1f20144cee31<br>
8a8a463c596a5db0ffde8948b4c0c8d2d7e3f97f9c2a7520eec4cce5</span><span style="color:green">**02820101**</span>00bf8188<br>
2048eff9f1be04e26a4bf258e523ce2c443bc362d9edd5db326db66abdfd287839b219f2


In between these headers we can see two full values! <br>
The order of data in PEM encodings is n, e, d, p, q, d mod (p-1), d mod (q-1). <br>
I tested if they were prime and found that the first one was and the second one was not. <br>
Therefore the first one must be q and the second one must be d mod (p-1). <br>
Assuming e is the standard 65537, this is enough information to recover p as well, <br>
and thus the entire private key. <br>

```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import isPrime

q = 0x00d36f2093bd46887ea77f84d39fcbb782ad47b1b13bca08aec96afe3ddd66176931b5b5128989bf8e60ae30b985d93b7b8936bd92969d0b00d12d61287c28925348b1b1447f3541b4b6b35449cf175fc20c5b82a0fd47a59f602a73e1af46246889cfc950dac7c6f8d4674797f0fd814874c57afc936525575d0ab7970df48ad522b6f50a65b4219c8928499046322943fd1a0a7ed8830fbc49e96e5468a1c0eec10f81af8ea88e788fee0e8b042e576e8c04c4299896b547815dc04f7c80d6350d24001e08d52151e2090b1f40776d0826186ffb66431e00ea1e3a1d919f7d2c1826c5f4a3dcc6c697d0f44e865739c2056cee9a5c4a3a7db3a3233cde2a747d
assert isPrime(q)
dp = 0x2868fb4c6db80589ebeabf499ea0d03c9d6cbf84dc9188b21cf78def9daac3782b2c03b4a504180137bd5bf778c88fb48c267c9b73976006c94a490ef5bc07c6c1459a99a15cf028d44989c120fac79ac8576cfe91485138b7bba81bc26deb03c63e3b1dbe29da338fd321cf452d81700d60275f0ee7a81ed713aa556fc862b1ca686d4c378fc58de6a294cbbb16f01d70017a9c2403e6b232348d7f03928efae471430b5403979a871db55c8426fd2df5565306ccce1a796fa1bb2780006f2ad2e07bda14aeb3d182d0f50af0afebd3a11e4367d87a5b581214733fb96b1f20144cee318a8a463c596a5db0ffde8948b4c0c8d2d7e3f97f9c2a7520eec4cce5
e = 65537

for kp in range(3, e):
    p_mul = dp * e - 1
    if p_mul % kp == 0:
        p = (p_mul // kp) + 1
        if isPrime(p):
            break
n = p*q
d = pow(e, -1, (p-1)*(q-1))
key = RSA.construct((n,e,d,p,q))
pem = key.export_key('PEM')
print(pem.decode())
```

In the ctf there was a server we could use the recovered private key to connect to and get the flag: <br>

```
python solve.py > key.pem
chmod 600 key.pem
ssh hawking@0.cloud.chals.io -p 19149 -i key.pem
```
