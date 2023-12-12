---
permalink: /cryptography/other/cyberyolk-writeups
title: cyberyolk writeups
---

<b>
  
Challenges from <https://sites.google.com/view/cyberyolk/home>

<br>



# Topic For Me

Challenge:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import *
import os
import random
from secrets import FLAG

class Random():
    a, b, c = random.getrandbits(32), random.getrandbits(32), random.getrandbits(32)
    def __init__(self, s):
        self.randsss = s
    def randommm(self):
        self.randsss = (self.b * self.randsss + self.c) % self.a
        return self.randsss
    def result(self):
        return self.a,self.b,self.c

def encrypt(key, m):
    message = pad(m, 16)
    cipher = AES.new(key, AES.MODE_ECB)
    enkripsi = cipher.encrypt(message)
    return enkripsi.hex().encode()

key = os.urandom(16)
seed = random.randint(1111111111111111, 9999999999999999)
lol = Random(seed)
topic = [seed]
for i in range(10):
    topic.append(lol.randommm())
topicccc = [encrypt(key, str(i).encode()) for i in topic]
count = 0

while True:
    print('''=========================================
    1. Next topic
    2. Test ur topic
    3. Topic for me
    4. Guess my next topic
    5. My topic now
    6. Exit
=========================================''')
    pilihan = input("Choose: ")
    
    if pilihan == '1':
        count += 1
        if count >= 8:
            print('Limited..')
            exit(0)
        else:
            print('Next topic:', topicccc[count])
    
    elif pilihan == '2':
        topicccc_input = input('Topic that you want to test: ')
        topicccc = encrypt(key, topicccc_input.encode())
        print('My topic is:', topicccc)
    
    elif pilihan == '3':
        topicccc_input = input('Topic for me: ')
        result = encrypt(key, (topicccc_input + str(topic[count])).encode())
        print('Recv:', result)
    
    elif pilihan == '4':
        niiii = int(input("What's my last topic? "))
        if niiii == topic[-1]:
            print(f'GG {FLAG}')
        else:
            print(f'Wrong...')
        exit()
    
    elif pilihan == '5':
        print(f"Topic now: {topicccc[count]}")
    
    elif pilihan == '6':
        print('Bye!')
        exit()
    
    else:
        print("Wrong!")
        exit()
```

<br>

Solve:

<br>

First we use option 3 as an encryption oracle to do an AES-ECB padding attack and recover the first few LCG states.

Then we can recover the LCG parameters and use those to send the next (11th) value and get the flag.

<br>

```python
from pwn import remote, process
from string import digits
from tqdm import tqdm

def encryption_oracle(io, x):
    io.read()
    io.sendline(b"3")
    io.read()
    io.sendline(str(x).encode())
    return io.readline().decode().split()[1][2:-1]

def ecb_attack(io, l):
    k = 32
    n_of_zeros = k
    n_known_bytes = 0
    known_bytes = []
    recovered = []
    for _ in tqdm(range(l)):
        for i in digits:
            i = ord(i)
            plaintext = (n_of_zeros -2 - 2*n_known_bytes)* "0" + "".join([str(item) for item in known_bytes]) + str(hex(i)).replace("0x","").zfill(2) + (n_of_zeros - 2 - 2*n_known_bytes) * "0"
            ciphertext = encryption_oracle(io, bytes.fromhex(plaintext).decode())
            block_1 = ciphertext[:k]
            block_2 = ciphertext[k:k*2]
            if(block_1 == block_2):
                recovered.append(i)
                n_known_bytes +=1
                known_bytes.append(str(hex(i)).replace("0x","").zfill(2))
                break
    return int(bytes(recovered))

def recover_states(io):
    states = []
    for _ in range(7):
        s = ecb_attack(io, 16)
        states.append(s)
        io.read()
        io.sendline(b"1")
    return states

def recover_lcg_params(states):
    PR.<b,c> = PolynomialRing(ZZ)
    g1, g2, a = Ideal([x1*b+c-x2 for x1, x2 in zip(states[:-1], states[1:])]).groebner_basis()
    b = g1.univariate_polynomial().roots()[0][0] % a
    c = g2.univariate_polynomial().roots()[0][0] % a
    return a, b, c

def nxt(io):
    io.read()
    io.sendline(b"1")

def solve():
    #io = remote("0.tcp.ap.ngrok.io", "11985")
    io = process(["python", "server.py"])

    states = recover_states(io)
    a, b, c = recover_lcg_params(states)

    x = states[0]
    for _ in range(10):
        x = (b*x+c) % a

    io.read()
    io.sendline(b"4")
    io.read()
    io.sendline(str(x).encode())
    flag = io.read().decode()
    if "Wrong" in flag:
        error()
    print(flag)

while True:
    try:
        solve()
        break
    except:
        pass

# CBY{how_D1d_u_do_th4t_9514aff45418e1aa1eea6202c50800c1}
```
