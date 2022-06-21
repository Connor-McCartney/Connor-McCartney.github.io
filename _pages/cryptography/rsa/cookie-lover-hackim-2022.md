---
permalink: /cryptography/rsa/cookie-lover-hackim-2022
title: Cookie Lover - HackIM CTF 2022
---


[Challenge files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2022/HackIM/cookie_lover)

```python
def sign(msg : bytes):
    # I will not talk about cookies.
    if b'cookie' in msg:
        return 0
    # no control characters allowed in message
    if any([c < 32 for c in msg]):
        return 0
    return pow(bytes_to_long(msg), key.d, key.n)
```

<br>

There was a signature oracle that let's you choose a message m and returns $$m^d \ (mod \ n)$$ <br>
The same key is always used and the goal is to sign 'I love cookies.' <br>
We can do this by factorising m into $$k \cdot \frac{m}{k}$$ <br>

Then $$k^d \cdot (\frac{m}{k})^d \ \ (mod \ n) \ = k^d \cdot \frac{m^d}{k^{\ d}} \ \ (mod \ n) = m^d \ \ (mod \ n)$$

<br>

```python
from Crypto.Util.number import *
from pwn import *

def read():
    for i in range(4):
        io.readline()
io = remote('52.59.124.14', 10301) 
read()

# signature attack by factorising m
m = bytes_to_long(b'I love cookies.')
x1 = (long_to_bytes(m // 30051184098398543))
x2 = (long_to_bytes(30051184098398543))

io.sendline(b"1:" + x1)
s1 = int(io.readline().decode().replace("\n",""))
read()

io.sendline(b"1:" + x2)
s2 = int(io.readline().decode().replace("\n",""))
read()

# now signature of original message is s1*s2
io.sendline(b"2:" + str(s1*s2).encode() )
print(io.readline().decode())
#ENO{F4ct0r_and_Conqu3r!}
```
