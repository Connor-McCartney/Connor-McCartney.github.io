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
