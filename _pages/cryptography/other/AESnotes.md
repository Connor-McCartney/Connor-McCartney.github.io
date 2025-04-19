---
permalink: /cryptography/other/AESnotes
title: AES notes
---


<br>

<br>


# CBC

```python
from Crypto.Cipher import AES
from os import urandom
from pwn import xor

p1, p2, p3, p4 = b'a'*16, b'b'*16 , b'c'*16, b'd'*16
key = urandom(16)
iv = urandom(16)
p = p1 + p2 + p3 + p4

ct = AES.new(key=key, mode=AES.MODE_CBC, iv=iv).encrypt(p)
c1, c2, c3, c4 = ct[:16], ct[16:32], ct[32:48], ct[48:]

# how does the encryption work?
def ECB_enc(x):
    return AES.new(key, AES.MODE_ECB).encrypt(x)

assert c1 == ECB_enc(xor(p1, iv))
assert c2 == ECB_enc(xor(p2, c1))
assert c3 == ECB_enc(xor(p3, c2))
assert c4 == ECB_enc(xor(p4, c3))
...

# and decryption?
def ECB_dec(x):
    return AES.new(key, AES.MODE_ECB).decrypt(x)

assert p1 == xor(ECB_dec(c1), iv)
assert p2 == xor(ECB_dec(c2), c1)
assert p3 == xor(ECB_dec(c3), c2)
assert p4 == xor(ECB_dec(c4), c3)
...
```

<br>

<br>

# Padding attack

```python
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom
from pwn import xor

def oracle(iv, ct):
    cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
    pt = cipher.decrypt(ct)  
    try:
        unpad(pt, 16)
        return True
    except:
        return False

def attack(c):
    r = b''
    for i in reversed(range(16)):
        s = bytes([16 - i] * (16 - i))
        for b in range(256):
            iv_ = b'\x00'*i + xor(s, bytes([b]) + r)
            if oracle(iv_, c):
                r = bytes([b]) + r
                break
    return r

plaintext = b'secret!!!!!!!!!!'
KEY = urandom(16)
iv = urandom(16)
ct = AES.new(KEY, AES.MODE_CBC, iv=iv).encrypt(plaintext)
assert attack(ct) == AES.new(KEY, AES.MODE_ECB).decrypt(ct)
print(xor(iv, attack(ct)))
```


<br>

# A quirk of pycrytodome

It will change the IV on the second encryption/decryption...


```python
from Crypto.Cipher import AES
from pwn import xor


C = AES.new(key=b'0'*16, mode=AES.MODE_CBC, iv=b'1'*16)
pt = b'a'*16 + b'b'*16
enc = C.encrypt(pt)

C = AES.new(key=b'0'*16, mode=AES.MODE_CBC, iv=b'1'*16)
print(C.decrypt(enc)) # correct
print(C.decrypt(enc)) # IV gets changed lol
print(C.decrypt(enc)) # same iv
print(C.decrypt(enc)) # same iv
print(C.decrypt(enc)) # same iv
print(C.decrypt(enc)) # same iv
print(C.decrypt(enc)) # same iv

print()


def ECB_dec(x):
    return AES.new(key=b'0'*16, mode=AES.MODE_ECB).decrypt(x)


C = AES.new(key=b'0'*16, mode=AES.MODE_CBC, iv=b'1'*16)
ct_correct = C.encrypt(pt)
#C = AES.new(key=b'0'*16, mode=AES.MODE_CBC, iv=b'1'*16)
ct_wrong = C.encrypt(pt)
print('correct iv', xor(ECB_dec(ct_correct[:16]), b'a'*16))
print('changed iv', xor(ECB_dec(ct_wrong[:16]), b'a'*16))
```

<br>

