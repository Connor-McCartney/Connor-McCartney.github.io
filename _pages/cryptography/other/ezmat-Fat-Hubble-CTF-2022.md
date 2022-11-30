---
permalink: /cryptography/other/ezmat-Fat-Hubble-CTF-2022
title: ezmat - Fat Hubble CTF 2022
---

<br>

[Challenge](https://github.com/Connor-McCartney/CTF_Files/tree/main/2022/Fat-Hubble-CTF/ezmat)

<br>

```py
G = random_matrix(GF(2), n, m)
G[randint(0, n-1)] = pad_m1
G = G.change_ring(ZZ)

v = random_matrix(GF(p), 1, n)
w = v * G
```

Challenge: Recover G given w.

<br>

```python
from Crypto.Util.number import long_to_bytes
from string import printable

def is_printable(flag):
    for c in flag:
        if chr(c) not in printable:
            return False 
    return True

################### part 1 ###########################
#https://eprint.iacr.org/2020/461.pdf

def allpmones(v):
    return len([vj for vj in v if vj in [-1, 0, 1]]) == len(v)

def orthoLattice(b, x0):
    m = b.length()
    M = Matrix(ZZ, m, m)
    for i in range(1, m):
        M[i, i] = 1
    M[1:m, 0] = -b[1:m] * inverse_mod(b[0], x0)
    M[0, 0] = x0
    for i in range(1, m):
        M[i, 0] = mod(M[i, 0], x0)
    return M

def allones(v):
    if len([vj for vj in v if vj in [0, 1]]) == len(v):
        return v
    if len([vj for vj in v if vj in [0, -1]]) == len(v):
        return -v
    return None

def recoverBinary(M5):
    lv = [allones(vi) for vi in M5 if allones(vi)]
    n = M5.nrows()
    for v in lv:
        for i in range(n):
            nv = allones(M5[i] - v)
            if nv and nv not in lv:
                lv.append(nv)
            nv = allones(M5[i] + v)
            if nv and nv not in lv:
                lv.append(nv)
    return Matrix(lv)

def kernelLLL(M):
    n = M.nrows()
    m = M.ncols()
    if m < 2 * n:
        return M.right_kernel().matrix()
    K = 2 ^ (m // 2) * M.height()
    MB = Matrix(ZZ, m + n, m)
    MB[:n] = K * M
    MB[n:] = identity_matrix(m)
    MB2 = MB.T.LLL().T
    assert MB2[:n, : m - n] == 0
    Ke = MB2[n:, : m - n].T
    return Ke

def attack(m, n, p, h):
    x0 = p
    b = vector(h)
    M = orthoLattice(b, x0)
    print("LLL...")
    M2 = M.LLL()
    MOrtho = M2[: m - n]
    ke = kernelLLL(MOrtho)
    if n > 170:
        return
    beta = 2
    while beta < n:
        if beta == 2:
            M5 = ke.LLL()
        else:
            M5 = M5.BKZ(block_size=beta)
        if len([True for v in M5 if allpmones(v)]) == n:
            break
        if beta == 2:
            beta = 10
        else:
            beta += 10
    MB = recoverBinary(M5)
    print("  Number of recovered vector = ", MB.nrows())
    print("  Number of recovered vector.T = ", MB.ncols())
    for row in MB:
        flag_part1 = long_to_bytes(int("".join(map(str, row[:167])), 2))
        if is_printable(flag_part1):
            return flag_part1
    assert False

from output import w, p, MM
flag_part1 = attack(330, 60, p, w)

################### part 2 ###########################
e = 0x10001
MM = Matrix(GF(2), MM)
print("matrix exponentiation...")
M = MM ** int(pow(e, -1, MM.multiplicative_order()))

for row in M:
    flag_part2 = long_to_bytes(int("".join(map(str, row[:167])), 2))
    if is_printable(flag_part2):
        break

print(flag_part1.decode() + flag_part2.decode())
#flag{634b9828-aa75-11ec-ad2c-00155d24943f}
```
