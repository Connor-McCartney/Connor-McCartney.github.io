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


---

<br>

<br>

<br>


Solve:

Well don't let the ChaCha trick you into thinking this is about stream cipher shenanigans, it's more mathematical. 


This was the first chall I've tried that deals with Poly1305, so I had lots of research to do, here's a dump:

<https://l3ak.team/2024/04/21/plaid24/>

<https://zenn.dev/kurenaif/articles/2a005936de308a>

<https://github.com/tl2cents/AEAD-Nonce-Reuse-Attacks>

<https://github.com/kalmarunionenctf/kalmarctf/tree/main/2024/crypto/PolyCG1305>

<https://datatracker.ietf.org/doc/html/rfc7539>

<https://github.com/ph4r05/py-chacha20poly1305/blob/master/chacha20poly1305/poly1305.py>

<https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/Cipher/ChaCha20.py#L244>

<https://github.com/Legrandin/pycryptodome/blob/master/src/poly1305.c>


---

Well first I learned what the 1305 means:

```py
sage: p = 2**130 - 5
sage: is_prime(p)
True
```


<br>



Now to look at the chall, if we just keep sending 'need', we can collect infinite sample of `print(f"my MIND was {enc(plaintext=None)[1].hex()}")`

That is, we have access to as many 16-byte MAC tags as we like.

Now I needed to learn how these MAC tags are created. 

<https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/Cipher/ChaCha20.py#L244>

Here we see r and s are derived from the key and nonce. The key and nonce are static in the chall, so r and s are both static too!

r and s come from 16 bytes, so they are both <2**128. Also note everything seems to use little endian. 


In Crypto/Cipher/ChaCha20_Poly1305.py we see how the ciphertext is modified:

```py
    def _compute_mac(self):
        """Finalize the cipher (if not done already) and return the MAC."""

        if self._mac_tag:
            assert(self._status == _CipherStatus.PROCESSING_DONE)
            return self._mac_tag

        assert(self._status != _CipherStatus.PROCESSING_DONE)

        if self._status == _CipherStatus.PROCESSING_AUTH_DATA:
            self._pad_aad()

        if self._len_ct & 0x0F:
            self._authenticator.update(b'\x00' * (16 - (self._len_ct & 0x0F)))

        self._status = _CipherStatus.PROCESSING_DONE

        self._authenticator.update(long_to_bytes(self._len_aad, 8)[::-1])
        self._authenticator.update(long_to_bytes(self._len_ct, 8)[::-1])
        self._mac_tag = self._authenticator.digest()
        return self._mac_tag
```

We have no aad (additional associated data) in this chall so that is ignored. 

<br>

From [this writeup](https://l3ak.team/2024/04/21/plaid24/) we see the input is usually `AD || pad(AD) || C || pad(C) || len(AD) || len(C)` but `C || pad(C) || len(AD) || len(C)` with no aad. 

As a one-liner, 

```python
msg = ct + b'\x00' * ((16 - len(ct) % 16) % 16) + (0).to_bytes(8,'little') + len(ct).to_bytes(8,'little')
```


<br>

<br>


