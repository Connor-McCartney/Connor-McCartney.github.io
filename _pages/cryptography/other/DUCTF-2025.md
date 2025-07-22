---
permalink: /cryptography/other/DUCTF-2025
title: DUCTF 2025
---


<br>

<br>

<https://github.com/DownUnderCTF/Challenges_2025_Public/tree/main/crypto>

<br>

<br>


# yet another login

Challenge:

```python
#!/usr/bin/env python3

from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from hashlib import sha256
from secrets import randbits
import os

FLAG = os.getenv('FLAG', 'DUCTF{FLAG_TODO}')

class TokenService: 
    def __init__(self):
        self.p = getPrime(512)
        self.q = getPrime(512)
        self.n = self.p * self.q
        self.n2 = self.n * self.n
        self.l = (self.p - 1) * (self.q - 1)
        self.g = self.n + 1
        self.mu = pow(self.l, -1, self.n)
        self.secret = os.urandom(16)

    def _encrypt(self, m):
        r = randbits(1024)
        c = pow(self.g, m, self.n2) * pow(r, self.n, self.n2) % self.n2
        return c

    def _decrypt(self, c):
        return ((pow(c, self.l, self.n2) - 1) // self.n) * self.mu % self.n

    def generate(self, msg):
        h = bytes_to_long(sha256(self.secret + msg).digest())
        return long_to_bytes(self._encrypt(h))

    def verify(self, msg, mac):
        h = sha256(self.secret + msg).digest()
        w = long_to_bytes(self._decrypt(bytes_to_long(mac)))
        return h == w[-32:]


def menu():
    print('1. Register')
    print('2. Login')
    return int(input('> '))


def main():
    ts = TokenService()
    print(ts.n)

    while True:
        choice = menu()
        if choice == 1:
            username = input('Username: ').encode()
            if b'admin' in username:
                print('Cannot register admin user')
                exit(1)
            msg = b'user=' + username
            mac = ts.generate(msg)
            print('Token:', (msg + b'|' + mac).hex())
        elif choice == 2:
            token = bytes.fromhex(input('Token: '))
            msg, _, mac = token.partition(b'|')
            if ts.verify(msg, mac):
                user = msg.rpartition(b'user=')[2]
                print(f'Welcome {user}!')
                if user == b'admin':
                    print(FLAG)
            else:
                print('Failed to verify token')
        else:
            exit(1)


if __name__ == '__main__':
    main()
```

<br>

Solve:

<br>

```python
from os import urandom
from Crypto.Util.number import bytes_to_long, getPrime
from hashlib import sha256
from random import randint
from tqdm import trange

def E(h):
    r = randint(0, 2**1024)
    mac = ((1 + h*n) * pow(r, n, n2)) % n2
    return mac

def D(c):
    return ((pow(c, l, n2) - 1) // n) * mu % n

def verify(mac):
    return h == D(mac) % 2**256

p, q = getPrime(512), getPrime(512)
n = p*q
n2 = n*n
secret = urandom(16)
l = (p - 1) * (q - 1)
mu = pow(l, -1, n)
h = bytes_to_long(sha256(secret + b'user=connor').digest())
print(f'{h = }')
mac = E(h)




# paillier homomorphic properties
x = randint(0, n)
y = randint(0, n)
assert (x+y) % n == D(E(x) * E(y))                              # (1)
assert (x*y) % n == D(pow(E(x), y, n2))                         # (2)

# add a non-encrypted integer
assert y == D(pow(n+1, y, n2)) % n2 
assert (x + y) % n == D(E(x) * pow(n+1, y, n2))                 # (3)




# now to solve h bit-by-bit (lsb towards msb)
# of course we need some way to compare our guess (h_lsb) with the actual h
# use subtraction for comparison, h-h_lsb, the lower bits will be 0 if correct
# but the oracle only tells us if the (lower 256 bits) of the decrypted value is equal to h
# so the idea is to begin with h, 
# then shift our comparison h-h_lsb towards the msb, 
# and then add it so that the lsb of the comparison overlap with the msb of h
# h + (h-h_lsb)*2**(255-b)


for b in range(256):
    h_lsb = int(h % 2**(b+1))
    assert (h + (h-h_lsb)*2**(255-b)) % 2**256 == h

    while True:
        h_lsb = randint(0, 2**(b+1)-1)
        if h_lsb != int(h % 2**(b+1)):
            break
    assert (h + (h-h_lsb)*2**(255-b)) % 2**256 != h


for b in trange(256):
    h_lsb = int(h % 2**(b+1))
    assert h-h_lsb == D(E(h)*pow(n+1, -h_lsb, n2))                                                # using (3)
    assert (h-h_lsb)*2**(255-b) == D(pow(E(h)*pow(n+1, -h_lsb, n2), 2**(255-b), n2))              # using (2)
    assert h + (h-h_lsb)*2**(255-b) == D(E(h) * pow(E(h)*pow(n+1, -h_lsb, n2), 2**(255-b), n2))   # using (1)
    assert h + (h-h_lsb)*2**(255-b) == D(mac * pow(mac*pow(n+1, -h_lsb, n2), 2**(255-b), n2))     # sub E(h) = mac


recovered_h = 0
for b in trange(256):
    if not verify(mac * pow(mac*pow(n+1, -recovered_h, n2), 2**(255-b), n2)):
        recovered_h += 2**b
print(recovered_h)
assert h == recovered_h
```

That'll solve us h = sha256(secret + b'user=connor')

Next step is SHA256 length extension

you can use <https://github.com/stephenbradshaw/hlextend/blob/master/hlextend.py>

<br>

```python
import hlextend
import hashlib
from os import urandom

secret = urandom(16)
h_connor = hashlib.sha256(secret + b'user=connor').digest()

extender = hlextend.sha256()
m_admin = extender.extend(appendData=b'user=admin', knownData=b'user=connor', secretLength=16, startHash=h_connor.hex())
h_admin = bytes.fromhex(extender.hexdigest())

print(m_admin)
assert hashlib.sha256(secret + m_admin).digest() == h_admin
```

<br>

Final remote solver:

```python
from pwn import remote
from Crypto.Util.number import bytes_to_long, long_to_bytes
from random import randint 
from tqdm import trange
import hlextend

def register(username):
    io.recvuntil(b'Login\n> ')
    io.sendline(b'1')
    io.recvuntil(b'Username: ')
    io.sendline(username)
    recv = bytes.fromhex(io.recvline().decode().split()[-1])
    return bytes_to_long(recv[len('user=') + len(username) + 1:])

def verify(msg, mac):
    io.recvuntil(b'Login\n> ')
    io.sendline(b'2')
    token_payload = (msg + b'|' + long_to_bytes(mac)).hex()
    io.recvuntil(b'Token: ')
    io.sendline(token_payload.encode())
    return b'Welcome' in io.recvline()

def E(h):
    r = randint(0, 2**1024)
    mac = ((1 + h*n) * pow(r, n, n2)) % n2
    return mac

io = remote('chal.2025.ductf.net', 30010)
n = int(io.recvline())
n2 = n**2

mac = register(b'connor')

# solve h
h_connor = 0
for b in trange(256):
    if not verify(b'user=connor', mac * pow(mac*pow(n+1, -h_connor, n2), 2**(255-b), n2)):
        h_connor += 2**b
h_connor = long_to_bytes(h_connor)

# length extension
extender = hlextend.sha256()
m_admin = extender.extend(appendData=b'user=admin', knownData=b'user=connor', secretLength=16, startHash=h_connor.hex())
h_admin = int(extender.hexdigest(), 16)

# profit
assert verify(m_admin, E(h_admin))
print(io.recvline())

# DUCTF{now_that_youve_logged_in_its_time_to_lock_in}
```



<br>

<br>

# SH-RSA

Challenge:

```python
#!/usr/bin/env python3

from Crypto.Util.number import long_to_bytes, bytes_to_long
from gmpy2 import mpz, next_prime
from hashlib import shake_128
import secrets, signal, os

def H(N, m):
    return shake_128(long_to_bytes(N) + m).digest(8)

def sign(N, d, m):
    return pow(mpz(bytes_to_long(H(N, m))), d, N)

def verify(N, e, m, s):
    return long_to_bytes(pow(s, e, N))[:8] == H(N, m)

def main():
    p = int(next_prime(secrets.randbits(2048)))
    q = int(next_prime(secrets.randbits(2048)))
    N = p * q
    e = 0x10001
    d = pow(e, -1, (p - 1) * (q - 1))

    print(f'{N = }')
    print(f'{e = }')

    for i in range(92):
        m = long_to_bytes(i)
        s = sign(N, d, m)
        print(m.hex(), hex(s))

    signal.alarm(46)

    s = int(input('s: '), 16)
    if verify(N, e, b'challenge', s):
        print(os.getenv('FLAG', 'DUCTF{test_flag}'))
    else:
        print('Nope')

if __name__ == '__main__':
    main()
```

<br>

Solve:

We have a bunch of signatures with small m_i < 2**64

$${s_i}^e \pmod n = m_i$$

If we let our target msb, t = bytes_to_long(b'challenge'), then the actual target should be shifted to as large as we can but still less than n. 

n is 4096 bits, the msb is 64 bits, and also leave some extra wiggle room, say 8 bits

shift = 2**(4096-64-8)

Then our actual target can be anywhere between t*shift and (t+1)*shift
