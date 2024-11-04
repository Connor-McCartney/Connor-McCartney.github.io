---
permalink: /cryptography/small-roots/d_high
title: d_high
---

<br>

It's a chinese chall sent to me. It got 7 solves. 

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

io1 = process(["python", "server.py"])
io2 = process(["python", "server.py"])
c_list = []

def io1_func(io):
    b_list =[]
    b_list_2 =[]


    public_key = io.recvuntil(b")\n")

    for i in range(100):
        buf=  io.sendafter(b'[-] b:',b'1\n')   
        #print(buf)
        # CX = int(buf.split()[3].decode())
        # print(CX)
        buf_res = io.recvline()
        #print(buf_res)
        if(b'correct' in buf_res):
            b_list.append(b'1\n')
            b_list_2.append(1)
        else:
            b_list.append(b'0\n')
            b_list_2.append(0)
        print(b_list_2)
    return b_list

def io2_func(io,b_list):
    public_key = io.recvuntil(b")\n")
    xx = public_key.decode().split()
    n = int(xx[-2][1:-1])
    e = int(xx[-1][:-1])
    print("public_key",public_key)
    print(io.recvline())
    c = int(io.recvline().split()[-1])
    for i in range(100):
        buf=  io.sendafter(b'[-] b:',b_list[i])   
        #print(buf)
        # CX = int(buf.split()[3].decode())
        # print(CX)
        buf_res = io.recvline()
        #print(buf_res)
    return n, e, c
        

        

b_list = io1_func(io1)   

n, e, c = io2_func(io2,b_list)

#io2.interactive()
d_, blind = io2.recv().decode().split()[-1][1:-2].split(",")
d_ = int(d_)
blind = int(blind)


from Crypto.Util.number import *
from tqdm import trange


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

