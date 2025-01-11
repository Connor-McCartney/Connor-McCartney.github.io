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

So basically we need to do a ciphertext forgery. Maybe option 1 isn't needed. 

<br>

I split the plaintext into it's 4 16-bytes blocks (p1, p2, p3, p4) with corresponding ciphertext blocks (c1, c2, c3, c4).

We want to choose c4 at random and then work backwards. 

<br>

