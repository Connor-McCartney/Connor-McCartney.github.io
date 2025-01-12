---
permalink: /cryptography/other/EnchantedOracle-UofTCTF2025
title: Enchanted Oracle - UofT CTF 2025
---


<br>

<br>

Challenge:


```python
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

print("Welcome to the AES-CBC oracle!")
key = open("key", "rb").read()
while True:
    print("Do you want to encrypt the flag or decrypt a message?")
    print("1. Encrypt the flag")
    print("2. Decrypt a message")
    choice = input("Your choice: ")

    if choice == "1":
        cipher = AES.new(key=key, mode=AES.MODE_CBC)
        ciphertext = cipher.iv + \
            cipher.encrypt(pad(b"random", cipher.block_size))

        print(f"{b64encode(ciphertext).decode()}")

    elif choice == "2":
        line = input().strip()
        data = b64decode(line)
        iv, ciphertext = data[:16], data[16:]

        cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
        try:
            plaintext = unpad(cipher.decrypt(ciphertext),
                              cipher.block_size).decode('latin1')
        except Exception as e:
            print("Error!")
            continue

        if plaintext == "I am an authenticated admin, please give me the flag":
            print("Victory! Your flag:")
            print(open("flag.txt").read())
        else:
            print("Unknown command!")
```

<br>

<br>

Solve:

<br>

So basically we need to do a ciphertext forgery. In fact, choice 1 is not needed at all!

<br>

I split the plaintext into its 4 16-byte blocks (p1, p2, p3, p4) with corresponding ciphertext blocks (c1, c2, c3, c4).

We want to choose c4 at random and then work backwards. 

<br>

For example:

```python
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from os import urandom
from pwn import xor

KEY = urandom(16)

plaintext = b"I am an authenticated admin, please give me the flag"
p1 = b'I am an authenti'
p2 = b'cated admin, ple'
p3 = b'ase give me the '
p4 = pad(b'flag', 16)
assert plaintext == unpad(p1+p2+p3+p4, 16)

def ECB_dec(x):
    return AES.new(KEY, AES.MODE_ECB).decrypt(x)

c4 = urandom(16)
c3 = xor(p4, ECB_dec(c4))
c2 = xor(p3, ECB_dec(c3))
c1 = xor(p2, ECB_dec(c2))
forged_iv = xor(p1, ECB_dec(c1))
forged_ct = c1+c2+c3+c4

print(unpad(AES.new(key=KEY, mode=AES.MODE_CBC, iv=forged_iv).decrypt(forged_ct), 16))
```

<br>

<br>

Now, just swap out the ECB_dec function for the classic CBC padding attack!

And implement batched requests for a big speedup.

<br>

Final solver:

```python
from Crypto.Util.Padding import pad
from base64 import b64encode
from os import urandom
from pwn import xor, process, remote
from tqdm import trange

def attack(c):
    r = b''
    for i in trange(15, -1, -1):
        s = bytes([16 - i] * (16 - i))
        payload = b''
        for b in range(256):
            iv_ = b'\x00'*i + xor(s, bytes([b]) + r)
            payload += b'2\n'
            payload += b64encode(iv_ + c) + b'\n'
        io.send(payload)
        out = io.recvlines(numlines=256*4)
        b = out[::4].index(b'Your choice: Unknown command!')
        r = bytes([b]) + r
    return r

p1 = b'I am an authenti'
p2 = b'cated admin, ple'
p3 = b'ase give me the '
p4 = pad(b'flag', 16)

#io = process(['python', 'aes-cbc.py'])
io = remote('34.162.82.42', 5000)
io.recv()

c4 = urandom(16)
c3 = xor(p4, attack(c4))
c2 = xor(p3, attack(c3))
c1 = xor(p2, attack(c2))
forged_iv = xor(p1, attack(c1))
forged_ct = c1+c2+c3+c4

io.sendline(b'2')
io.sendline(b64encode(forged_iv + forged_ct))
io.interactive()
# uoftctf{y3s_1_kn3w_y0u_w3r3_w0r7hy!!!}
```
