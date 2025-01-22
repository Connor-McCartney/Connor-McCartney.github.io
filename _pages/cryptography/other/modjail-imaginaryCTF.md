---
permalink: /cryptography/other/modjail-imaginaryCTF
title: modjail - imaginary CTF
---

<br>
<br>


Challenge:

```python
#!/usr/bin/python3
from Crypto.Util.number import getPrime, long_to_bytes
from secret import flag
from secrets import randbelow

p = getPrime(1024)
r = randbelow(p)
print(f'{r} mod {p}')
n = int(input())
if n%p != r:
    print('no')
    exit()
print(eval(long_to_bytes(n)))
```

<br>

Solve:

My idea is send `flag# ...<random bytes>` (except null '\x00')

`M * 256**j + x ≡ r (mod p)`

Choose j precisely so that we have exactly 128 bytes (size of p), rearrange for x, and hope that x has no null bytes. 

If it does, then rety until it doesn't. 

<br>

```python
from pwn import remote
from Crypto.Util.number import *

M = bytes_to_long(b'flag#')

def main():
    io = remote('155.248.210.243', 42114)
    recv = io.recvline().split()
    r = int(recv[0])
    p = int(recv[2])

    j = 1024//8
    x = (r - M * 256**j) % p
    n = M * 256**j + x

    io.sendline(str(n).encode())
    print(io.recv())

    io.close()

while True:
    main()

# ictf{p1Ck3d_y0Ur_W@y_pa$7_th3_P1cKy_m0du1u5}
```

<br>

<br>

# modjail2 

Challenge:

```python
#!/usr/bin/python3
from Crypto.Util.number import getPrime, long_to_bytes
from secret import flag
from secrets import randbelow
from time import sleep

p = getPrime(256)
r = randbelow(p)
print(f'{r} mod {p}')
n = int(input())
if n%p != r:
    print('no')
    exit()

m = long_to_bytes(n).decode()
strikes = 0 # 3 and you're out!
for c in m:
    sleep(0.01)
    if not (ord('a') <= ord(c) <= ord('z')):
        strikes += 1
        print(f'strike {strikes}{"!"*strikes}')
        if strikes >= 3: exit()

print(eval(m))
```

<br>

<br>

Solve:

For a valid message, we can send this for some x in range 1 to 127:

```py
    n = bytes_to_long(b'flag#' + <... any junk in a to z...> + bytes([x]))
```
