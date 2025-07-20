---
permalink: /cryptography/other/DUCTF-2025
title: DUCTF 2025
---


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

Solve:







<br>

<br>

# good game spawn point


Challenge:

```python
#!/usr/bin/env python3
import os
import secrets
import hashlib
from Crypto.Util.number import getPrime
from Crypto.PublicKey import ECC

FLAG = os.getenv("FLAG", "DUCTF{testflag}")

# https://neuromancer.sk/std/nist/P-256
order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 * 0x1


def ec_key():
    eck = ECC.generate(curve="p256")
    secret = int(eck.d)
    public_key = {
        "x": int(eck.public_key().pointQ.x),
        "y": int(eck.public_key().pointQ.y),
    }
    return secret, public_key


def paillier_key():
    p = getPrime(1024)
    q = getPrime(1024)
    n = p * q
    return p, q, n


def mta_response(ciphertext, n, secret):
    beta = secrets.randbelow(n)
    nsq = n * n

    # E(plaintext * secret)
    mta_response = pow(ciphertext, secret, nsq)

    # E(beta)
    r = secrets.randbelow(n)
    beta_enc = (pow(r, n, nsq) * pow(n + 1, beta, nsq)) % nsq

    # E(plaintext * secret + beta)
    mta_response = (mta_response * beta_enc) % nsq

    return mta_response, beta


def zk_schnorr(beta):
    r = secrets.randbelow(order)
    r_pub = ECC.construct(curve="p256", d=r % order).public_key().pointQ
    beta_pub = ECC.construct(curve="p256", d=beta % order).public_key().pointQ

    challenge_input = f"{beta}{order}{beta_pub}{r_pub}".encode()
    c_hash = int.from_bytes(hashlib.sha256(challenge_input).digest(), "big")
    z = (r + beta * c_hash) % order

    return {
        "hash": c_hash,
        "r_pub": {
            "x": int(r_pub.x),
            "y": int(r_pub.y),
        },
        "beta_pub": {
            "x": int(beta_pub.x),
            "y": int(beta_pub.y),
        },
    }


def main():
    print(
        """
        it's 4pm on a school afternoon. you just got home, tossed your bag
        on the floor, and turned on ABC3. it's time.. for GGSP
        """
    )

    secret, public_key = ec_key()
    print("public key:", public_key)

    p, q, n = paillier_key()
    print("paillier key:", {"p": p, "q": q})

    for _ in range(5):
        c = int(input("ciphertext:"))
        response, beta = mta_response(c, n, secret)
        print("mta response:", response)

        proof = zk_schnorr(beta)
        print("zk schnorr:", proof)

    guess = int(input("guess secret:"))
    if guess == secret:
        print("nice :o", FLAG)
    else:
        print("bad luck")


if __name__ == "__main__":
    main()
```

<br>

Solve: 





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





<br>

<br>

# certvalidated

<br>

Attatchments:

<br>

Dockerfile

```
FROM ubuntu:22.04

RUN apt-get update \
    && apt-get install -y wget socat python3-pip swig \
    && rm -r /var/lib/apt/lists/*

RUN pip install endesive==2.18.5

USER 1000
WORKDIR /home/ctf

COPY ./flag.txt /home/ctf/
COPY ./root.crt /home/ctf/
COPY ./certvalidated.py /home/ctf/certvalidated.py

COPY --chmod=755 entrypoint.sh /home/ctf/entrypoint.sh
ENTRYPOINT ["/home/ctf/entrypoint.sh"]
```

<br>

entrypoint.sh

```bash
#!/usr/bin/env bash
socat -dd TCP-LISTEN:1337,reuseaddr,fork EXEC:./certvalidated.py
```

<br>

root.crt

```
-----BEGIN CERTIFICATE-----
MIIDgzCCAmugAwIBAgIUe6f2tO34vYWqh/bz8BfNUdZpK8gwDQYJKoZIhvcNAQEL
BQAwUTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxFTATBgNVBAoM
DERvd25VbmRlckNURjEWMBQGA1UEAwwNRFVDVEYgUm9vdCBDQTAeFw0yNTA3MDQw
OTU4MTJaFw0yNjA3MDQwOTU4MTJaMFExCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApT
b21lLVN0YXRlMRUwEwYDVQQKDAxEb3duVW5kZXJDVEYxFjAUBgNVBAMMDURVQ1RG
IFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDY10s/2DsA
/1lfdnCiINf4ZZWguWRsdNo8xKZqm3i0hlWudiTVMlhRh8dBYl0YOA4bx06nL6cO
BT7NEV/wqZUiIcpDgtHAX/+ZWP3p5QM0rmk5nN5b3C8jIpjugjHifmooSCYRBFq9
hKMYdCsogYPwnINMDJ40MCIYsK54FRKV5PBSoC5bEjJ1KidZoGGKcMsbowTz1Rrz
4zZiZP4rJTF+uJGLdagpDB/9fN5xkmoTTCU6g2uoSMr0/BE+rxqdDMM42ecdhedM
mSp1F6yv88gW9vrINEnXUVUVK2EFbN6ljdAK4kPGHCEYKotruuJy66DpYriG1mrX
ZmHS1OZtSCw/AgMBAAGjUzBRMB0GA1UdDgQWBBTQt4qQPkvjMD2aaxDg/BTrl5P/
izAfBgNVHSMEGDAWgBTQt4qQPkvjMD2aaxDg/BTrl5P/izAPBgNVHRMBAf8EBTAD
AQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAMqOr/YShwJA0+GQ/GrRHkclNaamDkGNws
vklbTxMjloMmbMCJW5L0+bgl9c5Rk3Q7fGk8bWZ5mOadr7xQUqjuBHHGoKZ3Y2v/
Q6XSJ8JAnxIR/+HH+zePmHxOXRFEVdVe1uLlIMJWMu0mtPbvzxRHDH0j4t09dgcL
wE+de8+cUIa9E2yD/gnnuHl5L9nHWoZPZDu3KTohRfSYAux3sEZpbAnwPwBh7bic
H5mxH27Bx2SRELIA6NgVi5J3DHbEEUUEVxkgHzu7AoNa8zCgV0s0n/qjmF1U1DND
Zh1EkpMUUAvf1CFRHhlcM3JuqVUoCVuHDtY9fUGHMQbQR7b2dfBo
-----END CERTIFICATE-----
```

<br>

certvalidated.py

```python
#!/usr/bin/env python3

import base64
from endesive import plain

TO_SIGN = 'just a random hex string: af17a1f2654d3d40f532e314c7347cfaf24af12be4b43c5fc95f9fb98ce74601'
DUCTF_ROOT_CA = open('./root.crt', 'rb').read()

print(f'Sign this! <<{TO_SIGN}>>')
content_info = base64.b64decode(input('Your CMS blob (base64): '))

hashok, signatureok, certok = plain.verify(content_info, TO_SIGN.encode(), [DUCTF_ROOT_CA])

print(f'{hashok = }')
print(f'{signatureok = }')
print(f'{certok = }')

if all([hashok, signatureok, certok]):
    print(open('flag.txt', 'r').read())
```

<br>

<br>

<br>

Solve:
