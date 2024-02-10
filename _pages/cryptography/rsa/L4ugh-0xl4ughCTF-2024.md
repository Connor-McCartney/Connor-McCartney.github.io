---
permalink: /cryptography/rsa/L4ugh-0xl4ughCTF-2024
title: L4ugh - 0xl4ughCTF 2024
---

<br>

[Challenge Files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2024/0xL4ugh/L4ugh)

<br>

A nice challenge written by my friend mindflayer and Bebo!

This was a 3-part challenge, finding d_good, finding d_evil, and a CBC bit flipping attack.

To find d_good you can send the biggest number allowed then divide by it, negating <br>
the comparatively small error constant added.

Finding d_evil was interesting. We have pairs of n and e generated with the same d.

```python
assert d*e % phi == 1 
k = (e*d-1)//phi
assert e*d == 1 + k*phi
assert e*d == 1 + k*(N-p-q+1)
assert e*d - k*N - (1 + k*(-p-q+1)) == 0
# let x = (1 + k*(-p-q+1))
```

Only two pairs are needed to find d:

$$e_1\cdot d - k_1 \cdot N_1 = x_1$$

$$e_2\cdot d - k_2 \cdot N_2 = x_2$$

Rewriting as vector equations for LLL:

$$d \begin{bmatrix}e_2 \\ e_1 \\ 1\end{bmatrix} - k_1 \begin{bmatrix}0\\ N_1 \\ 0\end{bmatrix} - k_2 \begin{bmatrix}N_2 \\ 0 \\ 0\end{bmatrix} = \begin{bmatrix}x_1 \\ x_2 \\ d\end{bmatrix}$$


Full solve script:

```python
from pwn import remote, xor
from json import dumps

def s(x):
    io.sendline(dumps(x).encode())

io = remote("20.55.48.101", "1337")

io.read().decode()
s({"option":"1"})
exec(io.readline().decode())
exec(io.readline().decode())
e1, e2, _ = es
n1, n2, _ = Ns
B = Matrix([
    [1,  e1 ,  e2 ],
    [0,  n1 ,  0  ],
    [0,  0  ,  n2 ],
])
W = diagonal_matrix([2**512, 1, 1])
B = (B*W).LLL()/W
d_high = B[0][0]

s({"option":"2"})
io.read().decode()
io.sendline(f"{2**333-1}".encode())
exec(io.readline().decode().split("\t")[1])
d_low = RAND[0] // (2**333-1)
d = d_high * 2**333 + d_low


def initial_part():
    io.read()
    s({"option":"3", "d":str(d)})
    io.recvuntil(b"sign in")

initial_part()
s({"option":"1","user":"admin"})
pt=io.recvline().decode().strip()
token=bytes.fromhex(io.recvline().decode().strip())
iv, ct = token[:16], token[16:]
ct =ct[:10]+ xor(ct[10:15], b"true ", b"false") + ct[15:]
initial_part()
s({"option":"2","token":(iv+ct).hex()})
error_msg=io.recvline().decode().strip()
kk=eval(error_msg[17:])
new_iv = xor(kk[:16], iv,pt[:16].replace("'",'"').encode())
initial_part()
s({"option":"2","token":(new_iv+ct).hex()})
s({"option":"1"})
print(io.read().decode())
print(io.read().decode())

# 0xL4ugh{cryptocats_B3b0_4nd_M1ndfl4y3r}
```
