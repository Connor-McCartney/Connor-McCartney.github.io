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



I did from back to start first:

```python
from pwn import remote
from Crypto.Util.Padding import pad
from tqdm import tqdm

def encrypt(message):
    io.recvuntil(b' [Y|N]\n')
    io.sendline(b'Y')
    io.recvline()
    io.sendline(message)
    return bytes.fromhex(io.recvline().decode().split()[-1])

printable = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!'#$%&()*+,-./:;<=>?@[]^_`{|}~"
io = remote('ecbpp.kctf-453514-codelab.kctf.cloud', 1337)
flag = b''
o = 7

while b'wctf{' not in flag:
    if -(len(flag)+1) % 16 == ord('\n'):
        print('bruting extra char because of newlines in padding...')
        extra_char = tqdm(printable)
        o += 1
    else:
        extra_char = ['']
    for b in extra_char:
        brute = [pad(x.encode() + b.encode() + flag, 16) for x in printable]
        n = len(brute[0])
        enc = encrypt(b''.join(brute) + b'_'*o)
        lookup = {enc[n*i:n*(i+1)]: x.encode() for i, x in enumerate(printable)}
        correct = lookup.get(enc[-n:])
        if correct is not None:
            break
    flag = correct + b.encode() + flag
    print(flag)
    o += 1

#  wctf{1_m4d3_th15_fl4G_r34lly_l0ng_s0_th4t_y0u_w0ulD_h4v3_t0_d34L_w1th_muL7iPl3_bl0cKs_L0L}
```


<br>

But it seems from start to end is better:


```python
import string
from pwn import *

ALPHABET = string.ascii_letters + string.digits + "-_}{@!?$%^&*()~#/"

#p = process(["venv/bin/python3", "./chal.py"])
p = remote("ecbpp.kctf-453514-codelab.kctf.cloud", 1337)

p.recvline()
p.recvline()

def ecb_byte_at_a_time(known_pt=""):
    def enc(pt):
        p.sendline(b"Y")
        p.sendlineafter(b"message:", pt.encode())
        p.recvuntil(b"Your message is:  ")
        ct = bytes.fromhex(p.recvline().decode())
        return ct

    for i in range(90):
        padding = 15 - (i % 16)

        pt = ""
        for c in ALPHABET:
            pt += ("A" * padding) + known_pt + c

        dict_block_sizes = len(("A" * padding) + known_pt + "A")

        pt += "A" * padding
        ct = enc(pt)

        dict_cts = {}
        for j in range(len(ALPHABET)):
            c = ALPHABET[j]
            dict_cts[c] = ct[j*dict_block_sizes:(j+1)*dict_block_sizes][-16:]

        ct = ct[len(ALPHABET)*dict_block_sizes:]

        block_to_attack = (padding + i) // 16
        ct_block_to_attack = ct[block_to_attack * 16: (block_to_attack + 1) * 16]

        for c in ALPHABET:
            match = True
            for j in range(16):
                if ct_block_to_attack[j] != dict_cts[c][j]:
                    match = False
                    break

            if match:
                known_pt += c
                print(f"{known_pt}")
                break

    return known_pt

flag = ecb_byte_at_a_time(known_pt="wctf{")
print(flag) 
```
