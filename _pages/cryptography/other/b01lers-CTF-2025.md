---
permalink: /cryptography/other/b01lers-CTF-2025
title: b01lers CTF 2025
---

<br>

<br>



# Pesky CBC

```python
import secrets
from Crypto.Cipher import AES

try:
    with open('./flag.txt', 'r') as f:
        flag = f.read()
except:
    flag = 'bctf{REDACTED}'

key1 = secrets.token_bytes(32)
key2 = secrets.token_bytes(32)

def pesky_decrypt(ciphertext):
    assert len(ciphertext) % 16 == 0

    iv1 = secrets.token_bytes(16)
    iv2 = secrets.token_bytes(16)

    c1 = AES.new(key1, AES.MODE_CBC, iv1)
    c2 = AES.new(key2, AES.MODE_CBC, iv2)

    return c1.decrypt(c2.decrypt(ciphertext))

def main():
    cipher = AES.new(key2, AES.MODE_ECB)

    secret = secrets.token_bytes(16)
    ciphertext = cipher.encrypt(secret)

    print('Here is the encrypted secret:')
    print(ciphertext.hex())
    print()

    print('Here are some hints for you ^_^')
    for _ in range(8):
        random_value = secrets.token_bytes(16)
        ciphertext = cipher.encrypt(random_value)
        print(random_value.hex())
        print(ciphertext.hex())
    print()

    while True:
        print('Options:')
        print('1: pesky decrypt')
        print('2: guess secret')
        choice = input('>> ').strip()

        if choice == '1':
            ciphertext = bytes.fromhex(input('>> '))
            print(pesky_decrypt(ciphertext).hex())
        elif choice == '2':
            guess = bytes.fromhex(input('>> '))
            if secret == guess:
                print('Here is your flag :)')
                print(flag)
                return
            else:
                print('lmao skill issue')
                return
        else:
            print('Invalid Choice')
            return

if __name__ == '__main__':
    main()
```

<br>

<br>


Solve:

Let's analyse how pesky_decrypt works. 

```python
from os import urandom
from pwn import xor
from Crypto.Cipher import AES

def ECB_dec(x, key):
    return AES.new(key, AES.MODE_ECB).decrypt(x)

key1 = urandom(32)
key2 = urandom(32)

def pesky_decrypt(ciphertext):
    iv1 = urandom(16)
    iv2 = urandom(16)
    c1 = AES.new(key1, AES.MODE_CBC, iv1)
    c2 = AES.new(key2, AES.MODE_CBC, iv2)
    return c1.decrypt(c2.decrypt(ciphertext))

c1, c2, c3 = urandom(16), urandom(16), urandom(16)
payload = c1 + c2 + c3
recv = pesky_decrypt(payload)
o1, o2, o3 = recv[:16], recv[16:32], recv[32:48]
assert o3 == xor(ECB_dec(xor(ECB_dec(c3, key2), c2), key1), ECB_dec(c2, key2), c1) 
```


If we create some payload 3 blocks long, then the third received block is useful (the first 2 have the unknown iv1, iv2 in them)

Sending any payload more than 3 blocks doesn't really give anything else useful

```python
assert o3 == xor(ECB_dec(xor(ECB_dec(c3, key2), c2), key1), ECB_dec(c2, key2), c1)
```

Let's simplify this. 

Firstly we can just set c1 to 0, then xoring with that doesn't change.

let's call c3 X, and call c2 Y. 

And also call g1(x) = ECB_dec(x, key1), g2(x) = ECB_dec(x, key2)

Then it becomes this:

```python
def g1(x):
    return ECB_dec(x, key1)

def g2(x):
    return ECB_dec(x, key2)

def query(X, Y):
    payload = b'\x00'*16 + Y + X
    recv = pesky_decrypt(payload)
    return recv[32:48]

X, Y = urandom(16), urandom(16)
assert query(X, Y) == xor(g1(xor(g2(X), Y)), g2(Y))  # g1(g2(X) xor Y) xor g2(Y)
```

<br>

And we start with 8 pairs of random x and g2(x). 

```py

g1_, g2_ = {}, {}
for _ in range(8):
    x = urandom(16)
    g2_[x] = g2(x)
```

<br>

Now let's see how we can use our query. 

---

query(X, Y) = g1(g2(X) xor Y) xor g2(Y)

We can rearrange for g1(g2(X) xor Y) = query(X, Y) xor g2(Y) (where we know g2(X) and g2(Y))

---

query(X, Y) = g1(g2(X) xor Y) xor g2(Y)

We can rearrange for g2(Y) = query(X, Y) xor g1(g2(X) xor Y) 

If we send Y = g2(X) xor Z, g1(g2(X) xor Y) becomes g1(g2(X) xor g2(X) xor Z) = g1(Z)

so choose some Z and X where we know g2(X) and g1(Z)

g2(g2(X) xor Z) = query(X, g2(X) xor Z) xor g1(Z) 

---

```python
g1_, g2_ = {}, {}
for _ in range(8):
    x = urandom(16)
    g2_[x] = g2(x)

def expand_g1(X, Y):
    g1_[xor(g2_[X], Y)] = xor(query(X, Y),  g2_[Y])

def expand_g2(X, Z):
    g2_[xor(g2_[X], Z)] = xor(query(X, xor(g2_[X], Z)), g1_[Z])

for _ in range(200):
    expand_g1(random.choice(list(g2_.keys())), random.choice(list(g2_.keys())))
    expand_g2(random.choice(list(g2_.keys())), random.choice(list(g1_.keys())))

for x, g1x in g1_.items():
    assert g1x == g1(x)

for x, g2x in g2_.items():
    assert g2x == g2(x)
```

<br>

<br>



---


<br>

Local solver:


```python
from os import urandom, environ
environ['TERM'] = 'xterm'
from pwn import xor
from Crypto.Cipher import AES
from Crypto.Util.number import *
import random

def ECB_dec(x, key):
    return AES.new(key, AES.MODE_ECB).decrypt(x)

key1 = urandom(32)
key2 = urandom(32)

def pesky_decrypt(ciphertext):
    iv1 = urandom(16)
    iv2 = urandom(16)
    c1 = AES.new(key1, AES.MODE_CBC, iv1)
    c2 = AES.new(key2, AES.MODE_CBC, iv2)
    return c1.decrypt(c2.decrypt(ciphertext))

def g1(x):
    return ECB_dec(x, key1)

def g2(x):
    return ECB_dec(x, key2)

def query(X, Y):
    payload = b'\x00'*16 + Y + X
    recv = pesky_decrypt(payload)
    return recv[32:48]

X, Y = urandom(16), urandom(16)
assert query(X, Y) == xor(g1(xor(g2(X), Y)), g2(Y))  # g1(g2(X) xor y) xor g2(Y)

g1_, g2_ = {}, {}
for _ in range(8):
    x = urandom(16)
    g2_[x] = g2(x)

def expand_g1(X, Y):
    T = xor(g2_[X], Y)
    g1_[T] = xor(query(X, Y),  g2_[Y])
    return T

def expand_g2(X, Z):
    T = xor(g2_[X], Z)
    g2_[T] = xor(query(X, xor(g2_[X], Z)), g1_[Z])
    return T

while True:
    expand_g1(random.choice(list(g2_.keys())), random.choice(list(g2_.keys())))
    expand_g2(random.choice(list(g2_.keys())), random.choice(list(g1_.keys())))
    if len(g2_) > 128+20:
        break

for x, g1x in g1_.items():
    assert g1x == g1(x)

for x, g2x in g2_.items():
    assert g2x == g2(x)


def xor_subset(random_bytes, target):
    def bytes_to_binary(b):
        return [int(i) for i in f"{bytes_to_long(b):0128b}"]
    vecs = [bytes_to_binary(b) for b in random_bytes]
    M = Matrix(GF(2), vecs).transpose()
    if M.rank() != len(random_bytes):
        #print("all vectors not linearly independent")
        return []
    solve = M.solve_right(vector(bytes_to_binary(target)))
    return [v for s, v in zip(solve, random_bytes) if s]

cipher = AES.new(key2, AES.MODE_ECB)
secret = urandom(16)
print(f'          {secret = }')
ciphertext = cipher.encrypt(secret)

end_x = random.choice(list(g2_.keys()))
start = random.choice(list(g1_.keys()))
end = xor(g2_[end_x], ciphertext)
g1_end_plus_secret = query(end_x, ciphertext)

while True:
    g2_values = random.sample(list(g2_.values()), k=int(128))
    subset = xor_subset(g2_values, target=xor(start, end))
    if subset != [] and len(subset)%2 == 0:
        break

reversed = {v: k for k, v in g2_.items()}
current = start
for i in range(0, len(subset), 2):
    current = expand_g2(reversed[subset[i+0]], current)
    current = expand_g1(reversed[subset[i+1]], current)

assert current == end
secret = xor(g1_end_plus_secret, g1_[end])
print(f'recovered {secret = }')
```

<br>

<br>


Remote solver:

<br>

```python
from os import environ
environ['TERM'] = 'xterm'
from pwn import *
from Crypto.Util.number import *
from tqdm import trange

def expand_g1(X, Y):
    T = xor(g2_[X], Y)
    g1_[T] = xor(query(X, Y),  g2_[Y])
    return T

def expand_g2(X, Z):
    T = xor(g2_[X], Z)
    g2_[T] = xor(query(X, xor(g2_[X], Z)), g1_[Z])
    return T

def query(X, Y):
    payload = b'\x00'*16 + Y + X
    io.recvuntil(b'2: guess secret\n>> ')
    io.sendline(b'1')
    io.recv()
    io.sendline(payload.hex().encode())
    return bytes.fromhex(io.recvline().decode())[32:48]

def xor_subset(random_bytes, target):
    def bytes_to_binary(b):
        return [int(i) for i in f"{bytes_to_long(b):0128b}"]
    vecs = [bytes_to_binary(b) for b in random_bytes]
    M = Matrix(GF(2), vecs).transpose()
    if M.rank() != len(random_bytes):
        #print("all vectors not linearly independent")
        return []
    solve = M.solve_right(vector(bytes_to_binary(target)))
    return [v for s, v in zip(solve, random_bytes) if s]

#io = process(["python", "chall.py"])
io = remote("peskycbc.atreides.b01lersc.tf", 8443, ssl=True)
io.recvline()
ciphertext = bytes.fromhex(io.recvline().decode())
io.recvline()
io.recvline()

g1_, g2_ = {}, {}
for _ in range(8):
    g2x = bytes.fromhex(io.recvline().decode())
    x = bytes.fromhex(io.recvline().decode())
    g2_[x] = g2x

for _ in trange(128+20):
    expand_g1(random.choice(list(g2_.keys())), random.choice(list(g2_.keys())))
    expand_g2(random.choice(list(g2_.keys())), random.choice(list(g1_.keys())))

end_x = random.choice(list(g2_.keys()))
start = random.choice(list(g1_.keys()))
end = xor(g2_[end_x], ciphertext)
g1_end_plus_secret = query(end_x, ciphertext)

while True:
    g2_values = random.sample(list(g2_.values()), k=int(128))
    subset = xor_subset(g2_values, target=xor(start, end))
    if subset != [] and len(subset)%2 == 0:
        break

reversed = {v: k for k, v in g2_.items()}
current = start
for i in range(0, len(subset), 2):
    current = expand_g2(reversed[subset[i+0]], current)
    current = expand_g1(reversed[subset[i+1]], current)

assert current == end
secret = xor(g1_end_plus_secret, g1_[end])
print(f'recovered {secret = }')

io.recv()
io.sendline(b'2')
io.recv()
io.sendline(secret.hex().encode())
print(io.recv().decode())
```


```
bctf{neighbor_c5975dc61dbfd49a}
```
