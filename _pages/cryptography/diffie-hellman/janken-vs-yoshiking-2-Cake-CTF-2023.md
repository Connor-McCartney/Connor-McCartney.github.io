---
permalink: /cryptography/janken-vs-yoshiking-2-CakeCTF-2023
title: janken-vs-yoshiking-2 - Cake CTF 2023
---

<br>

[Challenge File](https://github.com/Connor-McCartney/CTF_Files/blob/main/2023/CakeCTF/server.sage)

<br>

Solve:

```python
from pwn import remote

def dlog(M, A):
    k = M.charpoly().splitting_field('x')
    J, P = M.jordan_form(k, transformation=True)
    Q = ~P * A * P
    return discrete_log(Mod(Q[0][0], p), Mod(J[0][0], p))

def str_to_mat(s):
    s = s[1:-1].split(", ")
    M = []
    for i in range(0, 25, 5):
        M.append([int(x) for x in s[i:i+5]])
    M = Matrix(GF(p), M)
    return M

def round():
    print(io.readline().decode())
    io.readuntil(b"is=")
    C = str_to_mat(io.readline().decode()[:-1])
    io.read()
    r = dlog(M, C)
    s = r%3
    if s == 0:
        s = 3
    io.sendline(str(s).encode())
    io.readline()
    io.readline()
    io.readline()
    print(io.readline().decode())
    io.readline()

io = remote("crypto.2023.cakectf.com", "10555")
p = 1719620105458406433483340568317543019584575635895742560438771105058321655238562613083979651479555788009994557822024565226932906295208262756822275663694111
io.readline()
io.readuntil(b"M: ")
M = str_to_mat(io.readuntil(b"]").decode())
io.readline()

for _ in range(100):
    round()

for _ in range(3):
    print(io.readline().decode())

# CakeCTF{though_yoshiking_may_die_janken_will_never_perish}
```
