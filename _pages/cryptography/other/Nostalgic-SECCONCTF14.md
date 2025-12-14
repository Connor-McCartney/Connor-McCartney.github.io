---
permalink: /cryptography/other/Nostalgic-SECCONCTF14
title: Nostalgic - SECCON CTF 14 (2025)
---

<br>
<br>


Challenge:

```python
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import os


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


FLAG = os.getenv("FLAG", "flag{dummy}")

key = get_random_bytes(32)
nonce = get_random_bytes(12)
SPECIAL_MIND = get_random_bytes(16)

print(f"my SPECIAL_MIND is {SPECIAL_MIND.hex()}")


def enc(plaintext=None):
    if plaintext == None:
        plaintext = get_random_bytes(15)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return ct, tag


special_rain = get_random_bytes(16)
special_ct, special_tag = enc(plaintext=special_rain)

print(f"special_rain_enc = {special_ct.hex()}")
print(f"special_rain_tag = {special_tag.hex()}")

while True:

    if (inp := input("what is your mind: ")) != "need":
        if enc(plaintext=xor(special_rain, bytes.fromhex(inp)))[1] == SPECIAL_MIND:
            print(f"I feel the same!!.. The flag is {FLAG}")
        else:
            print("No... not the same...")
        break
    else:
        print(f"my MIND was {enc(plaintext=None)[1].hex()}")
```



Solve:

Well don't let the ChaCha trick you into thinking this is about stream cipher shenanigans, it's more mathematical. 


This was the first chall I've tried that deals with Poly1305, so I had lots of research to do, here's a dump:

