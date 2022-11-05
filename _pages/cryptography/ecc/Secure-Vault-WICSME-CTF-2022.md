---
permalink: /cryptography/ecc/Secure-Vault-WICSME-CTF-2022
title: Secure Vault - WICSME CTF 2022
---

<br>

Challenge:

<br>

```python
#!/usr/bin/python3

import os
import random
import ecdsa
from hashlib import sha256
from sys import exit

get_k = (
    lambda: os.urandom(32)[random.randrange(0, 32)]
    ^ os.urandom(32)[random.randrange(0, 32)] + 1
)
def b2l(x): return int.from_bytes(x, "big")
def l2b(x): return x.to_bytes(64, "big")


sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=sha256)
vk = sk.get_verifying_key()

users = {"admin": ["flag{XXXXXXXXXXXXX}"]}
connected = 0
User = None


def welcome():
    print(
        "This is the vault of secrets! You can use it to keep secrets inside, don't worry they are perfectly safe  thanks to latest signing encryption. This is a beta version, you can only store 10 secrets."
    )


def view():
    if len(users[User]):
        print("\n".join(f"{i+1}] {secret}" for i,
              secret in enumerate(users[User])))
    else:
        print("No secrets to show")


def login():
    global connected, User
    data = input("login -> ")
    if "-" not in data:
        print("Wrong format")
        return
    creds, name = data.split("-", 1)
    if not creds.isdigit():
        print("Credentials must be integer")
        return
    if name in users and vk.verify(l2b(int(creds)), name.encode()):
        connected = 1
        User = name
        print(f"Succesfully logged as user : {name}")
        return
    print("Wrong signing key")


def register():
    global users
    name = input("name -> ")
    if name not in users:
        creds = b2l(sk.sign(name.encode(), k=get_k()))
        users[name] = []
        print("succesfully registered")
        print(f"login credentials : {creds}-{name}")
        return
    print("User already exist")


def add_secret():
    if len(users[User]) < 11:
        secret = input("secret -> ")
        users[User].append(secret)
        print("Secret has been succesfully added")
        return
    print("Max secrets limit reached")


def main():
    welcome()
    funcs = {0: [exit, login, register], 1: [exit, view, add_secret]}
    while True:
        choice = None
        if connected:
            print("1. View secrets")
            print("2. Add secret")
        else:
            print("1. login")
            print("2. register")

        print("0. Exit")

        while choice not in ["1", "2", "0"]:
            choice = input("> ")

        funcs[connected][int(choice)]()


if __name__ == "__main__":
    main()
```

<br>

Solve: 

$$
\text{priv} \equiv \frac{s1 \cdot k1 - z1}{r1} \equiv \frac{s2 \cdot k2 - z2}{r2} \ (mod \ n)
$$

```python
from pwn import remote
from hashlib import sha256
from tqdm import tqdm
from ecdsa import SECP256k1
from Crypto.Util.number import long_to_bytes, bytes_to_long


def read():
    print(io.read().decode())


def b2l(x):
    return int.from_bytes(x, "big")


def l2b(x):
    return x.to_bytes(64, "big")


io = remote("127.0.0.1", 1337)
read()

# Collect 2 signatures
io.sendline(b"2")
read()
io.sendline(b"random name 1")
S1 = l2b(int(io.read().decode().split()[5][:-7]))

io.sendline(b"2")
read()
io.sendline(b"random name 2")
S2 = l2b(int(io.read().decode().split()[5][:-7]))

r1 = b2l(S1[:32])
s1 = b2l(S1[32:])
r2 = b2l(S2[:32])
s2 = b2l(S2[32:])
n = SECP256k1.order
z1 = b2l(sha256(b"random name 1").digest())
z2 = b2l(sha256(b"random name 2").digest())

# bruteforce attack
for k1 in tqdm(range(256)):
    for k2 in range(256):
        if ((s1*k1-z1) * pow(r1, -1, n)) % n == ((s2*k2-z2) * pow(r2, -1, n)) % n:
            priv = ((s1*k1-z1) * pow(r1, -1, n)) % n

# send admin signature to get flag
k = 2
x = int((SECP256k1.generator * k).x())
y = int((SECP256k1.generator * k).y())
r = x % n
s = pow(k, -1, n) * (bytes_to_long(sha256(b"admin").digest()) + r * priv) % n

admin_sig = str(b2l(long_to_bytes(r) + long_to_bytes(s))) + "-admin"
io.sendline(b"1")
read()
io.sendline(admin_sig.encode())
read()
io.sendline(b"1")
read()
# flag{S4M3_K3yS_M34n5_7rouBLes_F0R_EC}
```
