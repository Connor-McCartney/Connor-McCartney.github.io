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

```
$ openssl x509 -in root.crt -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            7b:a7:f6:b4:ed:f8:bd:85:aa:87:f6:f3:f0:17:cd:51:d6:69:2b:c8
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=AU, ST=Some-State, O=DownUnderCTF, CN=DUCTF Root CA
        Validity
            Not Before: Jul  4 09:58:12 2025 GMT
            Not After : Jul  4 09:58:12 2026 GMT
        Subject: C=AU, ST=Some-State, O=DownUnderCTF, CN=DUCTF Root CA
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:d8:d7:4b:3f:d8:3b:00:ff:59:5f:76:70:a2:20:
                    d7:f8:65:95:a0:b9:64:6c:74:da:3c:c4:a6:6a:9b:
                    78:b4:86:55:ae:76:24:d5:32:58:51:87:c7:41:62:
                    5d:18:38:0e:1b:c7:4e:a7:2f:a7:0e:05:3e:cd:11:
                    5f:f0:a9:95:22:21:ca:43:82:d1:c0:5f:ff:99:58:
                    fd:e9:e5:03:34:ae:69:39:9c:de:5b:dc:2f:23:22:
                    98:ee:82:31:e2:7e:6a:28:48:26:11:04:5a:bd:84:
                    a3:18:74:2b:28:81:83:f0:9c:83:4c:0c:9e:34:30:
                    22:18:b0:ae:78:15:12:95:e4:f0:52:a0:2e:5b:12:
                    32:75:2a:27:59:a0:61:8a:70:cb:1b:a3:04:f3:d5:
                    1a:f3:e3:36:62:64:fe:2b:25:31:7e:b8:91:8b:75:
                    a8:29:0c:1f:fd:7c:de:71:92:6a:13:4c:25:3a:83:
                    6b:a8:48:ca:f4:fc:11:3e:af:1a:9d:0c:c3:38:d9:
                    e7:1d:85:e7:4c:99:2a:75:17:ac:af:f3:c8:16:f6:
                    fa:c8:34:49:d7:51:55:15:2b:61:05:6c:de:a5:8d:
                    d0:0a:e2:43:c6:1c:21:18:2a:8b:6b:ba:e2:72:eb:
                    a0:e9:62:b8:86:d6:6a:d7:66:61:d2:d4:e6:6d:48:
                    2c:3f
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                D0:B7:8A:90:3E:4B:E3:30:3D:9A:6B:10:E0:FC:14:EB:97:93:FF:8B
            X509v3 Authority Key Identifier:
                D0:B7:8A:90:3E:4B:E3:30:3D:9A:6B:10:E0:FC:14:EB:97:93:FF:8B
            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        0c:a8:ea:ff:61:28:70:24:0d:3e:19:0f:c6:ad:11:e4:72:53:
        5a:6a:60:e4:18:dc:2c:be:49:5b:4f:13:23:96:83:26:6c:c0:
        89:5b:92:f4:f9:b8:25:f5:ce:51:93:74:3b:7c:69:3c:6d:66:
        79:98:e6:9d:af:bc:50:52:a8:ee:04:71:c6:a0:a6:77:63:6b:
        ff:43:a5:d2:27:c2:40:9f:12:11:ff:e1:c7:fb:37:8f:98:7c:
        4e:5d:11:44:55:d5:5e:d6:e2:e5:20:c2:56:32:ed:26:b4:f6:
        ef:cf:14:47:0c:7d:23:e2:dd:3d:76:07:0b:c0:4f:9d:7b:cf:
        9c:50:86:bd:13:6c:83:fe:09:e7:b8:79:79:2f:d9:c7:5a:86:
        4f:64:3b:b7:29:3a:21:45:f4:98:02:ec:77:b0:46:69:6c:09:
        f0:3f:00:61:ed:b8:9c:1f:99:b1:1f:6e:c1:c7:64:91:10:b2:
        00:e8:d8:15:8b:92:77:0c:76:c4:11:45:04:57:19:20:1f:3b:
        bb:02:83:5a:f3:30:a0:57:4b:34:9f:fa:a3:98:5d:54:d4:33:
        43:66:1d:44:92:93:14:50:0b:df:d4:21:51:1e:19:5c:33:72:
        6e:a9:55:28:09:5b:87:0e:d6:3d:7d:41:87:31:06:d0:47:b6:
        f6:75:f0:68
```

<br>

<br>

