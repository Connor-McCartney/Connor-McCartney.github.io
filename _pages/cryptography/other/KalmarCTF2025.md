---
permalink: /cryptography/other/KalmarCTF2025
title: Kalmar CTF 2025
---

<br>
<br>

# basic sums

Challenge:

```python
with open("flag.txt", "rb") as f:
    flag = f.read()

# I found this super cool function on stack overflow \o/ https://stackoverflow.com/questions/2267362/how-to-convert-an-integer-to-a-string-in-any-base
def numberToBase(n, b):
    if n == 0:
        return [0]
    digits = []
    while n:
        digits.append(int(n % b))
        n //= b
    return digits[::-1]

assert len(flag) <= 45

flag = int.from_bytes(flag, 'big')

base = int(input("Give me a base! "))

if base < 2:
    print("Base is too small")
    quit()
if base > 256:
    print("Base is too big")
    quit()

print(f'Here you go! {sum(numberToBase(flag, base))}')
```

<br>

Solve:

There's a nice property, n is equivalent to the sum of the digits in any base b, mod b-1:

```python
def numberToBase(n, b):
    if n == 0:
        return [0]
    digits = []
    while n:
        digits.append(int(n % b))
        n //= b
    return digits[::-1]

n = 12345 # arbitrary example
for b in range(2, 257):
    assert n % (b-1) == sum(numberToBase(n, b)) % (b-1)
```

<br>

It's basically because b mod (b-1) is always 1. Then every power of b is just reduced to 1. 

If you want to see a concrete example:

```python
n = 51 
b = 3
print(numberToBase(n, b))
# [1, 2, 2, 0]


assert b % (b-1) == 1
assert 3 % 2 == 1

assert n == 0*3^0 + 2*3^1 + 2*3^2 + 1*3^3
assert n % (2) == (0*3^0 + 2*3^1 + 2*3^2 + 1*3^3) % 2
assert n % (2) == (0*1 + 2*1 + 2*1 + 1*1) % 2
assert n % (2) == (0 + 2 + 2 + 1) % 2
```


Or a more formal proof: <https://www.mathpages.com/home/kmath020/kmath020.htm>


<br>

Anyways, now we just have to collect many samples and CRT them to get the flag. 

A solve script:

```python
from pwn import remote, context
from sympy.ntheory.modular import crt
from Crypto.Util.number import long_to_bytes

with context.quiet:
    bases = []
    sums = []
    for b in range(256, 2, -1):
        io = remote('basic-sums.chal-kalmarc.tf', 2256)
        io.recv()
        io.sendline(str(b).encode())
        sums.append(int(io.recv().split()[-1]))
        bases.append(b-1)
        flag, _ = crt(bases, sums)
        print(long_to_bytes(flag))
# kalmar{At_least_it_wasnt_lattices_right???!?}
```

<br>

<br>

<br>

---

<br>

<br>

<br>

# Very Serious Cryptography

Challenge:


```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

with open("flag.txt", "rb") as f:
    flag = f.read()

key = os.urandom(16)

# Efficient service for pre-generating personal, romantic, deeply heartfelt white day gifts for all the people who sent you valentines gifts
for _ in range(1024):

    # Which special someone should we prepare a truly meaningful gift for? 
    recipient = input("Recipient name: ")

    # whats more romantic than the abstract notion of a securely encrypted flag?
    romantic_message = f'Dear {recipient}, as a token of the depth of my feelings, I gift to you that which is most precious to me. A {flag}'
    
    aes = AES.new(key, AES.MODE_CBC, iv=b'preprocessedlove')

    print(f'heres a thoughtful and unique gift for {recipient}: {aes.decrypt(pad(romantic_message.encode(), AES.block_size)).hex()}')
```

<br>

<br>

Solver:


```python
from pwn import remote

def send_batched(io, lines):
    io.send("".join([line + "\n" for line in lines]).encode())
    return [bytes.fromhex(line.decode().split()[-1]) for line in io.recvlines(len(lines))]

prefix = "Dear "
middle = ", as a token of the depth of my feelings, I gift to you that which is most precious to me. A "
charset = "abcdefghijklmnopqrstuvwxyz'{}_"
io = remote("very-serious.chal-kalmarc.tf", 2257)
flag = ""

while '}' not in flag:
    try:
        recipient = "_" * ((15 - len(prefix) - len(middle) - len(flag)) % 16)
        original = send_batched(io, [recipient])[0]
        brute = send_batched(io, [recipient + middle + flag + c for c in charset])
        l = len(prefix + recipient + middle + flag) + 1
        flag += {b[:l]: c for b, c in zip(brute, charset)}[original[:l]]
        print(flag)
    except EOFError:
        print('reached 1024 queries, opening new connection')
        io = remote("very-serious.chal-kalmarc.tf", 2257)
```
