---
permalink: /cryptography/rsa/krsa-INTIGRITICTF2024
title: krsa - INTIGRITI CTF 2024
---


<br>
<br>

Challenge:

```python
from Crypto.Util.number import *
import signal

def timeout_handler(signum, frame):
    print("Secret key expired")
    exit()

signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(300)

FLAG = "INTIGRITI{fake_flag}"
SIZE = 32

class Alice:
    def __init__(self):
        self.p = getPrime(1024)
        self.q = getPrime(1024)
        self.n = self.p*self.q
        self.e = 0x10001
    
    def public_key(self):
        return self.n,self.e
    
    def decrypt_key(self, ck):
        phi = (self.p-1)*(self.q-1)
        d = inverse(e, phi)
        self.k = pow(ck, d, n)

class Bob:
    def __init__(self):
        self.k = getRandomNBitInteger(SIZE)

    def key_exchange(self, n, e):
        return pow(self.k, e, n)

alice = Alice()
bob = Bob()

n,e = alice.public_key()
print("Public key from Alice :")
print(f"{n=}")
print(f"{e=}")

ck = bob.key_exchange(n, e)
print("Bob sends encrypted secret key to Alice :")
print(f"{ck=}")

alice.decrypt_key(ck)
assert(alice.k == bob.k)

try:
    k = int(input("Secret key ? "))
except:
    exit()

if k == bob.k:
    print(FLAG)
else:
    print("That's not the secret key")
```

<br>

Solve:

MITM attack:

<https://crypto.stackexchange.com/questions/2195/is-rsa-padding-needed-for-single-recipient-one-time-unique-random-message/2196#2196>

```python
from pwn import remote
from tqdm import trange

io = remote('krsa.ctf.intigriti.io', 1346)
print(io.recvline())
n = int(io.recvline().decode().split('=')[-1])
print(io.recvline())
print(io.recvline())
ck = int(io.recvline().decode().split('=')[-1])
print(io.recv())


lookup1 = {}
lookup2 = {}
for a in trange(1, 2**17):
    lookup1[ck * pow(a, -65537, n) % n] = a
for b in trange(1, 2**17):
    lookup2[pow(b, 65537, n)] = b
inter = set(lookup1.keys()).intersection(set(lookup2.keys()))
print(f'{inter = }')
for i in inter:
    a = lookup1[i]
    b = lookup2[i]
    k = a*b
    print(f'recovered {k = }')

io.sendline(str(k).encode())
io.interactive()
# INTIGRITI{w3_sh0uld_m33t_1n_th3_m1ddl3}
```
