---
permalink: /cryptography/other/easy-factoring-zer0pts-CTF-2023
title: easy_factoring - zer0pts CTF 2023
---

<br>

# Challenge

```python
import os
import signal
from Crypto.Util.number import *

flag = os.environb.get(b"FLAG", b"dummmmy{test_test_test}")

def main():
    p = getPrime(128)
    q = getPrime(128)
    n = p * q

    N = pow(p, 2) + pow(q, 2)

    print("Let's factoring !")
    print("N:", N)

    p = int(input("p: "))
    q = int(input("q: "))

    if isPrime(p) and isPrime(q) and n == p * q:
        print("yey!")
        print("Here you are")
        print(flag)
    else:
        print("omg")

def timeout(signum, frame):
    print("Timed out...")
    signal.alarm(0)
    exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(30)
    main()
    signal.alarm(0)
```

# Solve

Unlike the challenge title it isn't really factoring, more of diophantine equation.

Could be solved with [alpertron](https://www.alpertron.com.ar/METHODS.HTM) or sympy.

```python
from sympy.abc import x, y, t
from sympy.solvers.diophantine.diophantine import diop_quadratic
from Crypto.Util.number import isPrime
from pwn import remote

io = remote("crypto.2023.zer0pts.com", 10333)
print(io.readline().decode())
N = int(io.readline().decode().split()[-1])

print('solving...')
solve = diop_quadratic(x**2 + y**2 - N, t)
print('solved')

for p, q in solve:
    p, q = int(p), int(q)
    if isPrime(p) and isPrime(q):
        io.sendline(str(p).encode())
        io.sendline(str(q).encode())
        io.interactive()
```
