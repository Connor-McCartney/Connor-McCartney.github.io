---
permalink: /cryptography/rsa/Lost-Modulus-Again-HTB
title: Lost Modulus Again - HTB
---

<br>

# Challenge

```python
from Crypto.Util.number import getPrime, long_to_bytes, inverse
from os import urandom

flag = open('flag.txt', 'r').read().strip().encode()
class RSA:
    def __init__(self):
        self.p = getPrime(1024)
        self.q = getPrime(1024)
        self.e = 3
        self.n = self.p * self.q
        self.d = inverse(self.e, (self.p-1)*(self.q-1))
    def encrypt(self, data: bytes) -> bytes:
        pt = int(data.hex(), 16)
        ct = pow(pt, self.e, self.n)
        return long_to_bytes(ct)
    def decrypt(self, data: bytes) -> bytes:
        ct = int(data.hex(), 16)
        pt = pow(ct, self.d, self.n)
        return long_to_bytes(pt)

def main():
    #padding makes everything secure :lemonthink:
    def pad(data: bytes) -> bytes:
        return data+urandom(16)
    crypto = RSA()
    print ('Flag1 :', crypto.encrypt(pad(flag)).hex())
    print ('Flag2 :', crypto.encrypt(pad(flag)).hex())
    print( 'msg1 :', crypto.encrypt(b"Lost modulus had a serious falw in it , we fixed it in this version, This should be secure").hex())
    print( 'msg2 :', crypto.encrypt(b"If you can't see the modulus you cannot break the rsa , even my primes are 1024 bits , right ?").hex())
if __name__ == '__main__':
    main()

"""
Flag1 : 685dba88de1ecf0b4ae5bc84b7ee87f63eb37f697ca9a5ab6af9359341a2fbbf53b9502477cabb1658fdf775a34a0712b04d0fd2679b47ec088e0ab3c0a9a866198077a496bb1de138cd165ca28722dee7c4cc81ac0a3a179095f11981e9c7bcd590576169ed877b5692f42a7d9845bdb7c0bffd4e97541b65321de83e4083c1c8cc93eec59933f42655d7c0ad170ed9a3ea418b582e09a2692fc1965d8372cac678f0dabe1b0cbda93ac9b484feb9d2e96f3ab7e2fc6430da1931281c1870c637866be7fcd69c1b067e001887bb17a57ccd77532ea9dfaa0be1390db5511771dc9e03593e344bf0647ddac395b1fe80a86ad4ea4606fdb8a82fdcf9c846114c
Flag2 : 356f7e82071f321361075ee85f9b42922662559ed64b253c64ff37b52fe8dcf3ab3163079bc9a12e951f84d2f7a911cbf1b1e8d7cd759a128f21a89b625b07ded33443a2888ca9a455198fd5b4a3fb307f34c704b7dcad88685263f4c3f4cf37f1099f2bd188de72533308c25fc18948dda220e3693b7f3edb689ee489c14e7624932ee8928370c9c1d59b06d1071a259d64c38735b1b586082099919713b669a79e43329f0c20508620982d95b774a57d009540c2ef2835887d229273223272f86fb0b1740937d3fc83d7556ffe634a16fb1faf6125878b06f5d537c21260014e2e67ae47636cbce899c463a3669954253aac3aa89a1c800d3251cf6a36badf
msg1 : 0241f53c0690e3faccc3753b6064aef27341b5bef3a10fcbb362251e1f5474a055a04e631af1bb4542351f6051438fc6dbf2011f79cbd85bc667d1097b57818d01d11aa09db0ef221ccf8d9eb16903423702b64a534d49153b49dc47fd5597a96f2a6480d296d36d08ba3438cc193bba6ee2c3ea81ab4dbb029a737c3f5597c8e4b8db8ab06605443eb35160828bc78b1d889814d8811e89efae3d741a481a7bd09483df8ee6d32b56a8d7eb20b275cf3ba5936838da2893f82cbc469f1497f785603e72df1ae1f619e08834588f2e64dd5f4cbbdbc7357dadcd89dbd9e18b0948f9b3f8f6b0df217bd7e8ae5c89a20878ffb127e3cf862baa78cc67ec1012af
msg2 : 7499a590fcb19dd0880b77a0dd57f66f6055976100b10053adadaeec18c382c5c3d095b4edd6ee2a5dfdc5790b18ff96e54f093fa62d4b518c1bbe65ad3588a81a1723ce72798ddd06d1eca7be9332a7b754f85582c4c5800d0c778ec320fa53806d122b4f4e436ead12bdf05031d4c181416184932517da985ff503759d128761bd96009c43bf11e45ba60f495235d29a863b7a64d9752868dd9896563fe2cc91df6f092f6d4d7d600b4fbf2b52579a0f2657223a1092c067584aad9997540b25921513f96f2da0c26ffb2ee7578540efc50bc8ab0feeeb24e0e96ebc1e6310dbed880ec5d9788a86bebe72c4b5d9b5c66716e6b84021591372c823c6d78c4e
"""
```

<br>

# Solve

First recover n with gcd then solve with Coppersmith’s short pad attack:

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long

Flag1 = 0x685dba88de1ecf0b4ae5bc84b7ee87f63eb37f697ca9a5ab6af9359341a2fbbf53b9502477cabb1658fdf775a34a0712b04d0fd2679b47ec088e0ab3c0a9a866198077a496bb1de138cd165ca28722dee7c4cc81ac0a3a179095f11981e9c7bcd590576169ed877b5692f42a7d9845bdb7c0bffd4e97541b65321de83e4083c1c8cc93eec59933f42655d7c0ad170ed9a3ea418b582e09a2692fc1965d8372cac678f0dabe1b0cbda93ac9b484feb9d2e96f3ab7e2fc6430da1931281c1870c637866be7fcd69c1b067e001887bb17a57ccd77532ea9dfaa0be1390db5511771dc9e03593e344bf0647ddac395b1fe80a86ad4ea4606fdb8a82fdcf9c846114c
Flag2 = 0x356f7e82071f321361075ee85f9b42922662559ed64b253c64ff37b52fe8dcf3ab3163079bc9a12e951f84d2f7a911cbf1b1e8d7cd759a128f21a89b625b07ded33443a2888ca9a455198fd5b4a3fb307f34c704b7dcad88685263f4c3f4cf37f1099f2bd188de72533308c25fc18948dda220e3693b7f3edb689ee489c14e7624932ee8928370c9c1d59b06d1071a259d64c38735b1b586082099919713b669a79e43329f0c20508620982d95b774a57d009540c2ef2835887d229273223272f86fb0b1740937d3fc83d7556ffe634a16fb1faf6125878b06f5d537c21260014e2e67ae47636cbce899c463a3669954253aac3aa89a1c800d3251cf6a36badf
msg1 = 0x0241f53c0690e3faccc3753b6064aef27341b5bef3a10fcbb362251e1f5474a055a04e631af1bb4542351f6051438fc6dbf2011f79cbd85bc667d1097b57818d01d11aa09db0ef221ccf8d9eb16903423702b64a534d49153b49dc47fd5597a96f2a6480d296d36d08ba3438cc193bba6ee2c3ea81ab4dbb029a737c3f5597c8e4b8db8ab06605443eb35160828bc78b1d889814d8811e89efae3d741a481a7bd09483df8ee6d32b56a8d7eb20b275cf3ba5936838da2893f82cbc469f1497f785603e72df1ae1f619e08834588f2e64dd5f4cbbdbc7357dadcd89dbd9e18b0948f9b3f8f6b0df217bd7e8ae5c89a20878ffb127e3cf862baa78cc67ec1012af
msg2 = 0x7499a590fcb19dd0880b77a0dd57f66f6055976100b10053adadaeec18c382c5c3d095b4edd6ee2a5dfdc5790b18ff96e54f093fa62d4b518c1bbe65ad3588a81a1723ce72798ddd06d1eca7be9332a7b754f85582c4c5800d0c778ec320fa53806d122b4f4e436ead12bdf05031d4c181416184932517da985ff503759d128761bd96009c43bf11e45ba60f495235d29a863b7a64d9752868dd9896563fe2cc91df6f092f6d4d7d600b4fbf2b52579a0f2657223a1092c067584aad9997540b25921513f96f2da0c26ffb2ee7578540efc50bc8ab0feeeb24e0e96ebc1e6310dbed880ec5d9788a86bebe72c4b5d9b5c66716e6b84021591372c823c6d78c4e
p1 = bytes_to_long(b"Lost modulus had a serious falw in it , we fixed it in this version, This should be secure")
p2 = bytes_to_long(b"If you can't see the modulus you cannot break the rsa , even my primes are 1024 bits , right ?")

n = gcd(msg1-p1^3, msg2-p2^3)

def coppersmith_short_pad(C1, C2, N, e):
    P1.<x, y> = PolynomialRing(Zmod(N))
    P2.<y> = PolynomialRing(Zmod(N))
    g1 = (x^e - C1).change_ring(P2)
    g2 = ((x + y)^e - C2).change_ring(P2)
    res = g1.resultant(g2, variable=x)
    roots = res.univariate_polynomial().change_ring(Zmod(N)).small_roots(epsilon=0.04)
    diff = int(roots[0])

    #Franklin Reiter
    P3.<X> = PolynomialRing(Zmod(n))
    g1 = (X)^3 - Flag1
    g2 = (X + diff)^3 - Flag2
    while g2:
        g1, g2 = g2, g1 % g2
    m = -g1.monic()[0]
    return long_to_bytes(int(m))

flag = coppersmith_short_pad(Flag1, Flag2, n, e=3)
print(flag)
```
