---
permalink: /cryptography/other/WolvCTF2025
title: Wolv CTF 2025
---

<br>


# ECB++

Challenge:

```python
#!/usr/local/bin/python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import random

f = open('./flag.txt','r')
flag = f.read()

def encrypt(message):
    global flag
    message = message.encode()
    message += flag.encode()
    key = random.getrandbits(256)
    key = key.to_bytes(32,'little')
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    return(ciphertext.hex())

print("Welcome to my secure encryption machine!")
print("I'll encrypt all your messages (and add a little surprise at the end)")

while(True):
    print("Do you have a message to encrypt? [Y|N]")
    response = input()
    if(response == 'Y'):
        print("Gimme your message:")
        message = input()
        print("Your message is: ",encrypt(message))
    else:
        exit(0)
```

<br>

<br>

Solver:

