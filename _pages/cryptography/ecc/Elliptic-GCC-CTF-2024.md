---
permalink: /cryptography/ecc/Elliptic-GCC-CTF-2024
title: Elliptic - GCC CTF 2024
---

<br>

Challenge:

```python
from Crypto.Util.number import isPrime, bytes_to_long
import json
from flag import flag

print("I'm pretty nice, I let you choose my curve parameters")

p = int(input("p = "))
a = int(input("a = "))
b = int(input("bl = "))

assert int(p).bit_length() > 128, "Send a bigger number"
assert isPrime(p), "Send a prime"


E = EllipticCurve(GF(p),[a,b])
G = E.gens()[0]
o = G.order()
l = factor(o)

assert int(l[-1][0]).bit_length() >= 0x56
flag_int = bytes_to_long(flag.lstrip(b"GCC{").rstrip(b"}"))

bin_flag = [int(val) for val in bin(flag_int)[2:]]

points = [E.random_element() for _ in range(len(bin_flag))]

s = G*0

for i,val in enumerate(bin_flag):
	if val == 1:
		s += points[i]

print(json.dumps({"values":[[int(a) for a in point.xy()] for point in points]}),flush=True)
print(s.xy(),flush=True)
```


<br>

We're given a lot of freedom to choose all curve parameters, so there's probably several ways to create a weak curve and take discrete logarithms. 

We decided on Smart's attack. 

<https://www.monnerat.info/publications/anomalous.pdf>

ctfguy wrote a script to create the parameters:

```python
while True:
    n = randint(0, 2**128)
    p = (n + 1) ** 3 - n ** 3
    if is_prime(p):
        break

a = 0
for b in range(1, 10):
    E = EllipticCurve(GF(p), [a, b])
    if E.order() == p:
        print(f"{a = }")
        print(f"{b = }")
        print(f"{p = }")
```

Then we can take the discrete log of everything and turn it into a sort of subset sum problem mod G.order()

However, instead of trying to solve the subset sum traditionally, we can reconnect to the server 

multiple times to get multiple equations and solve the system directly. The flag bin length seems to be 127 so

we'll connect 127 times:

```python
from pwn import process, remote, context
from json import loads
from tqdm import trange, tqdm
from Crypto.Util.number import *

p = 1179413712842124676772771331562230869253636022705502169448503695361546387628711
a = 0
b = 3

E = EllipticCurve(GF(p), [a, b])
G = E.gens()[0]
assert G.order() == p

def log(P,Q):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])
    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break
    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break
    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp
    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()
    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)

flagbinlen = 127
logs_lst = []
s_lst = []
for _ in trange(flagbinlen):
    with context.quiet:
        #io = process(["sage", "server.sage"])
        io = remote("challenges1.gcc-ctf.com", "4000")
        io.recv()
        io.sendline(str(p).encode())
        io.recv()
        io.sendline(str(a).encode())
        io.recv()
        io.sendline(str(b).encode())
        points = loads(io.readline().decode())["values"]
        assert len(points) == flagbinlen
        sx, sy = eval(io.readline().decode())
        s = E(sx, sy)
        s = log(G, s)
        logs = [log(G, E(x, y)) for x, y in tqdm(points)]
        logs_lst.append(logs)
        s_lst.append(s)
        io.close()

M = []
for i in logs_lst:
    M.append(i)
M = Matrix(Zmod(G.order()), M)
target = vector(Zmod(G.order()), s_lst)
sol = M.solve_right(target)
print(sol)
print(long_to_bytes(int("".join(str(i) for i in sol), 2)))
```

```
[~/Desktop] 
$ time sage exp.sage 

...

100%|███████████████████████| 127/127 [46:44<00:00, 22.09s/it]

(1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0)
b'plz_enjoy_it_smh'

real    46m48.489s
```
