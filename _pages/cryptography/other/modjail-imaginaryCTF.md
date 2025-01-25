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

We should actually use LLL to find valid lsb in a to z!

<br>

```python
from os import environ
environ['TERM'] = 'konsole'
from pwn import remote
from Crypto.Util.number import *
load('https://gist.githubusercontent.com/Connor-McCartney/952583ecac836f843f50b785c7cb283d/raw/5718ebd8c9b4f9a549746094877a97e7796752eb/solvelinmod.py')

def main():
    io = remote('155.248.210.243', '42115')
    recv = io.recvline().split()
    r = int(recv[0])
    p = int(recv[2])

    N = 150 # somewhat arbitrary
    xs = [var(f'x{i}') for i in range(N)]
    eq = bytes_to_long(b'flag#') * 256**N + sum(x*256**i for i, x in enumerate(xs)) == r
    bounds = {x: (ord('a'), ord('z')) for x in xs}
    sol = solve_linear_mod([(eq, p)], bounds)
    if sol is None:
        print('no solution, retry')
        io.close()
        return
    else:
        sol = list(sol.values())
        print(f'{all([ord('a')<=i<=ord('z') for i in sol]) = }')
        n = b'flag#' + bytes(sol[::-1])
        print(n)
    

    io.sendline(str(bytes_to_long(n)).encode())
    print(io.recv().decode())

    io.close()

while True:
    main()

# ictf{a_c@R3fU1lY_Cr4fT3d_PayL04d!}
```


<br>

<br>

# modjail3

Challenge:

```python
#!/usr/bin/python3
from Crypto.Util.number import getPrime, long_to_bytes, bytes_to_long
from secret import flag

def wild(num):
    return bytes_to_long(repr(num).encode())

p = getPrime(64)
print(p)
n = int(input())
if n%p != wild(n)%p:
    print('no')
    exit()
print(eval(long_to_bytes(n)))
```


<br>

Solve:

We kinda need `n%p = bytes_to_long(str(n).encode()) % p`

<br>

```python
def wild(num):
    return bytes_to_long(repr(num).encode())

def my_wild(num):
    return sum([c*256**i for i,c in enumerate(str(num).encode()[::-1])])

n = 12345
assert wild(n) == my_wild(n)
```


<br>

```python
n = b'12345'
print([x-48 for x in n])
print(sum([(x-48)*10**i for i, x in enumerate(n[::-1])]))
```

<br>

```python
from Crypto.Util.number import getPrime, long_to_bytes, bytes_to_long

def wild(num):
    return bytes_to_long(repr(num).encode())

p = getPrime(64)
nbytes = b'flag#abcde'
n = bytes_to_long(nbytes)

LHS = n%p 
RHS = wild(n)%p


def bytes_to_int(x):
    return sum([c*256**i for i,c in enumerate(x[::-1])])

def repr_to_int(x):
    return sum([(c-48)*10**i for i,c in enumerate(x[::-1])])

nrepr = str(n).encode()
assert n == repr_to_int(nrepr)

xs = [ord(i) for i in 'abcde']
nbytes = [ord(i) for i in 'flag#'] + xs

lhs = bytes_to_int(nbytes)
rhs = bytes_to_int(nrepr)
assert LHS == lhs % p
assert RHS == rhs % p
```

<br>

But the problem is from going from bytes/repr to int, you need some modulus operation which is annoying

<br>

```python
ys = [int(i) for i in str(n)]
print(n%p)
print(sum([c*10**i for i,c in enumerate(ys[::-1])]) % p)
print(sum([(c+48)*256**i for i,c in enumerate(ys[::-1])]) % p)
print(sum([(c)*256**i for i,c in enumerate(nbytes[::-1])]) % p)
```

<br>


If you just want to solve for any n:

```python
load('https://gist.githubusercontent.com/Connor-McCartney/952583ecac836f843f50b785c7cb283d/raw/5718ebd8c9b4f9a549746094877a97e7796752eb/solvelinmod.py')
from Crypto.Util.number import * 

def check(num):
    return bytes_to_long(repr(num).encode()) % p == num % p

p = getPrime(64)

LEN = 30
ys = [var(f'y{i}') for i in range(LEN)]
bounds = {y: (0, 10) for y in ys}
lhs = sum([c*10**i for i,c in enumerate(ys[::-1])])
rhs = sum([(c+48)*256**i for i,c in enumerate(ys[::-1])])
sol = solve_linear_mod([(lhs==rhs, p)], bounds)
print(sol)
ys = list(sol.values())
n = int(''.join([str(i) for i in ys]))
print(f'found {n = }')
print(f'{check(n) = }')
```

<br>

Now my idea is to tweak the MSB of n so that we get 'flag#'

<br>


Local testing worked

```python
load('https://gist.githubusercontent.com/Connor-McCartney/952583ecac836f843f50b785c7cb283d/raw/5718ebd8c9b4f9a549746094877a97e7796752eb/solvelinmod.py')
from Crypto.Util.number import * 

def check(num):
    return bytes_to_long(repr(num).encode()) % p == num % p

p = getPrime(64)


LEN = 50
ys = [var(f'y{i}') for i in range(LEN)]
bounds = {y: (0, 10) for y in ys}
lhs = sum([c*10**i for i,c in enumerate(ys[::-1])])
rhs = sum([(c+48)*256**i for i,c in enumerate(ys[::-1])])
sol = solve_linear_mod([(lhs==rhs, p)], bounds)
ys = list(sol.values())
n = int(''.join([str(i) for i in ys]))
#print(f'found {n = }')
#print(f'{check(n) = }')


# messy way to get some prefix
l = len(long_to_bytes(n))
n_ = bytes_to_long(b'flag#' + b'\xff'*(l - 5))
ns_ = str(n_)
l = len(ns_)
i = l
while True:
    ns_ = ns_[:i] + '0'*(l-i)
    n_ = int(ns_)
    i -= 1
    if b'flag#' not in long_to_bytes(n_):
        break
    ns__ = ns_
    n__ = n_
print(ns__)
print(long_to_bytes(n__))
pre = [int(i) for i in ns__.split('00000')[0]] + [0]*10 # some arbitrary extra 0's
print(f'{pre = }')
print()



# now try resolve with pre
ys = [var(f'y{i}') for i in range(1 + LEN - len(pre))] # strange i have to add 1...
bounds = {y: (0, 10) for y in ys}
ys = pre + ys
lhs = sum([c*10**i for i,c in enumerate(ys[::-1])])
rhs = sum([(c+48)*256**i for i,c in enumerate(ys[::-1])])
sol = solve_linear_mod([(lhs==rhs, p)], bounds)
ys = pre + list(sol.values())
n = int(''.join([str(i) for i in ys]))
print(f'found {n = }')
print(f'{check(n) = }')
print(f'{long_to_bytes(n) = }')
```


<br>

and remote flag:


```python
from os import environ
environ['TERM'] = 'konsole'
from pwn import remote
load('https://gist.githubusercontent.com/Connor-McCartney/952583ecac836f843f50b785c7cb283d/raw/5718ebd8c9b4f9a549746094877a97e7796752eb/solvelinmod.py')
from Crypto.Util.number import * 

def check(num):
    return bytes_to_long(repr(num).encode()) % p == num % p

io = remote('155.248.210.243', 42111)
p = int(io.recvline())

LEN = 50
ys = [var(f'y{i}') for i in range(LEN)]
bounds = {y: (0, 10) for y in ys}
lhs = sum([c*10**i for i,c in enumerate(ys[::-1])])
rhs = sum([(c+48)*256**i for i,c in enumerate(ys[::-1])])
sol = solve_linear_mod([(lhs==rhs, p)], bounds)
ys = list(sol.values())
n = int(''.join([str(i) for i in ys]))

# messy way to get some prefix
l = len(long_to_bytes(n))
n_ = bytes_to_long(b'flag#' + b'\xff'*(l - 5))
ns_ = str(n_)
l = len(ns_)
i = l
while True:
    ns_ = ns_[:i] + '0'*(l-i)
    n_ = int(ns_)
    i -= 1
    if b'flag#' not in long_to_bytes(n_):
        break
    ns__ = ns_
    n__ = n_
pre = [int(i) for i in ns__.split('00000')[0]] + [0]*10 # some arbitrary extra 0's

# now try resolve with pre
ys = [var(f'y{i}') for i in range(1 + LEN - len(pre))] # strange i have to add 1...
bounds = {y: (0, 10) for y in ys}
ys = pre + ys
lhs = sum([c*10**i for i,c in enumerate(ys[::-1])])
rhs = sum([(c+48)*256**i for i,c in enumerate(ys[::-1])])
sol = solve_linear_mod([(lhs==rhs, p)], bounds)
ys = pre + list(sol.values())
n = int(''.join([str(i) for i in ys]))
print(f'found {n = }')
print(f'{check(n) = }')
print(f'{long_to_bytes(n) = }')


io.sendline(str(n).encode())
print(io.recv())
# ictf{tH3_B1t$iz3_of_T#e_bi7S1Ze_0F_7hE_Pr1m3_15_d3cRE@s!n6_L1ne4RLy...}
```
