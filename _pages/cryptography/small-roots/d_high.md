---
permalink: /cryptography/small-roots/d_high
title: d_high
---

<br>

All the above related contents are issued after authorization by @Halois

It's a chinese CTF chall sent to me by @Halois. It got 7 solves. 

```python
from Crypto.Util.number import getPrime,bytes_to_long
from secret import secret,flag
import random
import time
import os
import signal

def _handle_timeout(signum, frame):
    raise TimeoutError('function timeout')

timeout = 300
signal.signal(signal.SIGALRM, _handle_timeout)
signal.alarm(timeout)

random.seed(secret + str(int(time.time())).encode())

class RSA:
    def __init__(self):
        self.p = getPrime(512)
        self.q = getPrime(512)
        self.e = getPrime(128)
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.d = pow(self.e, -1, self.phi)  

    def get_public_key(self):
        return (self.n, self.e)
    
    def get_private_key(self, blind_bit=None, unknown_bit=None):
        if blind_bit is not None and unknown_bit is not None:
            blind = getPrime(blind_bit)
            d_ = ((int(self.d >> unknown_bit) // blind * blind) << unknown_bit) + int(self.d % blind)
            return (d_, blind)
        else:
            return (self.d, 0)
    
    def encrypt(self, m):
        if type(m) == bytes:
            m = bytes_to_long(m)
        elif type(m) == str:
            m = bytes_to_long(m.encode())
        return pow(m, self.e, self.n)
    
    def game(self,m0,m1,b):   
        return self.encrypt([m0,m1][b]) 

rsa = RSA()
token = os.urandom(66) 

print( "[+] Welcome to the game!")
print(f"[+] rsa public key: {rsa.get_public_key()}")

coins = 100
price = 100
while coins > 0:
    print("=================================")
    b = random.randint(0,1)
    c = rsa.game(
        b'bit 0:' + os.urandom(114), 
        b'bit 1:' + os.urandom(114), 
        b)
    print("[+] c:",c)
    guessb = int(input("[-] b:"))
    coins -= 1
    if guessb == b:
        price -= 1
        print("[+] correct!") 
    else: 
        print("[+] wrong!") 

if price != 0: 
    print("[-] game over!")
    exit()

blind_bit = 40
unknown_bit = 365

d_,blind = rsa.get_private_key(blind_bit, unknown_bit)

print( "[+] Now, you have permission to access the privkey!")
print(f"[+] privkey is: ({d_},{blind}).")
print(f"[+] encrypt token is: {rsa.encrypt(bytes_to_long(token))}")

guess_token = bytes.fromhex(input("[-] guess token:"))
if guess_token == token:
    print("[+] correct token, here is your flag:",flag)
else:
    print("[-] wrong token")
```

<br>

My solve script:

```python
load('https://raw.githubusercontent.com/Connor-McCartney/coppersmith/refs/heads/main/coppersmith.sage')
from pwn import *
from Crypto.Util.number import *
from tqdm import trange


io1 = process(["python", "server.py"])
io2 = process(["python", "server.py"])
c_list = []

def io_func(io1, io2):
    io1.recvuntil(b")\n")
    public_key = io2.recvuntil(b")\n")
    xx = public_key.decode().split()
    n = int(xx[-2][1:-1])
    e = int(xx[-1][:-1])
    for i in range(100):
        buf =  io1.sendafter(b'[-] b:',b'1\n')   
        buf_res = io1.recvline()
        if(b'correct' in buf_res):
            buf =  io2.sendafter(b'[-] b:',b'1\n')   
        else:
            buf =  io2.sendafter(b'[-] b:',b'0\n')   
        buf_res = io2.recvline()
    return n, e
        

n, e = io_func(io1, io2)
d_, blind = io2.recv().decode().split()[-1][1:-2].split(",")
d_ = int(d_)
blind = int(blind)


def solve(blind, d_, n, e):
    """
    not perfect
    assumptions: coppersmith bound will work (i brute small range)
                 first b bits of d are correct
    """
    blind_bit = 40
    unknown_bit = 365

    b = 615
    d_high = int(f'{d_:b}'[:b], 2)
    b = len(f'{d_:b}') - b


    k = (e*d_high*2**b-1)//n + 1

    PR.<x> = PolynomialRing(Zmod(e))
    f = (1 + k*(n+1-(x))) 
    s = int(f.roots()[0][0])

    S = n+1 - (e*d_high*2**b-1)//k
    D = isqrt(S^2-4*n)
    p_high = (S+D)//2


    PR.<x> = PolynomialRing(GF(e))
    f = x^2 - s*x + n
    possible_p_mod_e = [int(f.roots()[0][0]), int(f.roots()[1][0])]

    PR.<x> = PolynomialRing(GF(blind))
    d_mod_blind = int(f'{d_:b}'[-40:], 2)
    f = x + k*(n*x - x**2 - n + x) - x*e*d_mod_blind
    possible_p_mod_blind = [int(f.roots()[0][0]), int(f.roots()[1][0])]
    m = int(blind) * int(e)

    for p_mod_e in possible_p_mod_e:
        for p_mod_blind in possible_p_mod_blind:
            p_ = crt([p_mod_e, p_mod_blind], [e, blind])

            PR.<x> = PolynomialRing(Zmod(n))
            t_high = (p_high-p_)//m
            f = (t_high + x)*m + p_
            for bound in trange(95, 105):
                roots = univariate(f, X=2**(len(f'{t_high:b}')-bound), m=20, beta=0.49)
                if roots != []:
                    p = int(f(roots[0]))
                    assert is_prime(p) and n%p == 0
                    return p

p = solve(blind, d_, n, e)
q = n//p
d = pow(e, -1, (p-1)*(q-1))

print(io2.recvuntil(b"encrypt token is: "))
c = int(io2.recvline().decode())
token = pow(c, d, n)
print(io2.recv())
io2.sendline(token.hex().encode())
print(io2.recv())
```

<br>

<br>

Some explanations:

Part 1 is impossible without opening 2 connections. 

For part 2 I followed [this paper](https://eprint.iacr.org/2024/1329.pdf), but I also had to improvise 

and utilise the additional hint of d mod the small prime blind. 


### 1. Solve k through approximation

$$\text{d} \cdot \text{e} = 1 + \text{k}\cdot\text{phi}$$

$$\text{k} = \frac{\text{d} \cdot \text{e} - 1}{\text{phi}}$$

$$\text{k} \approx \frac{\text{d_high} \cdot \text{e} - 1}{\text{n}}$$

Depending on the parameter sizes, you actually get k exactly

### 2. Solve p_high through approximation

First get an approximation of p+q

$$\text{phi} = (p-1)(q-1) = n-p-q+1 = n+1-(p+q)$$

$$p+q = n+1-\text{phi}$$

$$p+q = n+1-\frac{\text{d} \cdot \text{e} - 1}{\text{k}}$$

$$p+q \approx n+1-\frac{\text{d_high} \cdot \text{e} - 1}{\text{k}}$$

Now let s = p+q and consider this equation

$$p^2 - s\cdot p + n = 0$$

Solving the quadratic for p with the approximation of p+q gives us 

an approximation of p where the high bits are correct.

### 3. Solve for p+q mod e

$$\text{d} \cdot \text{e} = 1 + \text{k}\cdot\text{phi}$$

$$0 \equiv 1 + \text{k}\cdot  (n+1-(p+q)) \text{ (mod e)}$$

### 4. Solve for p mod e

Simply reuse this equation, but mod e, and using the value found in step 3

$$p^2 - S\cdot p + n \equiv 0 \text{ (mod e)}$$

### 5. Solve for p mod r

$$p+q = n+1-\frac{\text{d} \cdot \text{e} - 1}{\text{k}}$$

multiply by p

$$p^2+p\cdot q = p\cdot n+p-\frac{p\cdot(\text{d} \cdot \text{e} - 1)}{\text{k}}$$

$$0 = k \cdot p\cdot n + k \cdot p - p\cdot(\text{d} \cdot \text{e} - 1) - k\cdot p^2 - k \cdot n$$

Replace d with h

$$0 \equiv k \cdot p\cdot n + k \cdot p - p\cdot(\text{h} \cdot \text{e} - 1) - k\cdot p^2 - k \cdot n \text{ (mod r)}$$

### 6. Let m = er, we combine p mod e and p mod r to get p mod m

### 7. Solve p 

$$p = \text{p_mod_m} + t\cdot m \ \ \ \ \text{    (for some integer t)}$$

Rearrange for t to get an approximation of t_high, then do coppersmith to solve p mod n

$$t = \frac{(p-\text{p_mod_m})}{m}$$

$$\text{t_high} \approx \frac{(\text{p_high}-\text{p_mod_m})}{m}$$

$$\text{p_mod_m} + t\cdot m \equiv 0  \ \ \ \ \text{ (mod p)}$$




Tests:

```python
flag = int.from_bytes(b'REDACTED')
p = random_prime(2**512)
q = random_prime(2**512)
e = random_prime(2**128)
r = random_prime(2**40)
n = p*q
c = pow(flag, e, n)
d = pow(e, -1, (p-1)*(q-1))
b = 300
d_high = (d>>b)<<b
h = int(d%r)


load('https://raw.githubusercontent.com/Connor-McCartney/coppersmith/refs/heads/main/coppersmith.sage')
d_low = d - d_high
assert d_low < 2**b
assert d == d_high + d_low

# 1
phi = (p-1)*(q-1)
k = (d*e-1) // phi
assert k == (d_high*e-1)//phi + 1

# 2
s = n + 1 - (d_high*e-1)//k
PR.<x> = PolynomialRing(RealField(1024))
f = x^2 - s*x + n
possible_p_high = [int(i) for i, _ in f.roots()]

# 3
PR.<x> = PolynomialRing(GF(e))
f = 1 + k*(n+1-x)
S = f.roots()[0][0] # p+q mod e

# 4
PR.<x> = PolynomialRing(GF(e))
f = x^2 - S*x + n
possible_p_mod_e = [i for i, _ in f.roots()]
assert p%e in possible_p_mod_e

# 5
PR.<x> = PolynomialRing(GF(r))
f = k*x*n + k*x - x*(h*e-1) - k*x^2 - k*n
possible_p_mod_r = [i for i, _ in f.roots()]
assert p%r in possible_p_mod_r

# 6
p_mod_e = p%e # testing only
p_mod_r = p%r # testing only
m = e*r
p_mod_m = crt(p_mod_e, p_mod_r, e, r)
assert p_mod_m == p % m

# 7
t = int(p - p_mod_m)//m #testing only
def same(t_high):
    # test only
    count = 0
    for x,y in zip(f'{t:b}', f'{t_high:b}'):
        if x!=y:
            return  count
        count += 1

for p_high in possible_p_high:
    t_high = int(p_high - p_mod_m)//m
    j = same(t_high)
    if j<10:
        continue
    PR.<x> = PolynomialRing(Zmod(n))
    f = m*(t_high+x) + p_mod_m 
    roots = univariate(f, X=2**(len(f'{t:b}')-j), beta=0.49, m=10)
    if roots == []:
        continue
    p = int(f(roots[0]))
    print(is_prime(p) and n%p == 0)
```
