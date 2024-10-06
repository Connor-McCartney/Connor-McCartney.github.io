---
permalink: /cryptography/ecc/Backdoor-IRONCTF2024
title: Backdoor - IRON CTF 2024
---

<br>

Challenge:

```python
from curve_operations import Point,Curve    # Custom module
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes

class Dual_EC:

    def __init__(self):
        p = 229054522729978652250851640754582529779
        a = -75
        b = -250
        self.curve = Curve(p,a,b)
        self.P = Point(97396093570994028423863943496522860154 , 2113909984961319354502377744504238189)
        self.Q = Point(137281564215976890139225160114831726699 , 111983247632990631097104218169731744696)
        self.set_initial_state()

    def set_initial_state(self):
        self.state = ???SECRET🤫???

    def set_next_state(self):
        self.state = self.curve.scalar_multiply(self.P, self.state).x

    def gen_rand_num(self):
        rand_point = self.curve.scalar_multiply(self.Q, self.state)
        rand_num = rand_point.x
        self.set_next_state()
        return rand_num

def main():
    prng = Dual_EC()
    flag = b'flag{test}'
    print("My PRNG has passed International Standards!!!")
    print("Here is a Sample Random Number to prove it to you : ", prng.gen_rand_num())
    key = long_to_bytes((prng.gen_rand_num() << 128) + prng.gen_rand_num())
    iv = long_to_bytes(prng.gen_rand_num())
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_bytes = cipher.encrypt(pad(flag, AES.block_size))
    print('Encrypted bytes : ',encrypted_bytes)

if(__name__ == "__main__"):
    main()
```

```
My PRNG has passed International Standards!!!
Here is a Sample Random Number to prove it to you :  222485190245526863452994827085862802196
Encrypted bytes :  b'BI\xd5\xfd\x8e\x1e(s\xb3vUhy\x96Y\x8f\xceRr\x0c\xe6\xf0\x1a\x88x\xe2\xe9M#]\xad\x99H\x13+\x9e5\xfd\x9b \xe6\xf0\xe10w\x80q\x8d'
```


<br>

<br>

Solve:

The curve parameters make a singular curve with an elliptic node. 

We can follow this link <https://crypto.stackexchange.com/questions/61302/how-to-solve-this-ecdlp>

We use an isomorphism to transfer the ecdlp to discrete log in GF(p).

The mapping function is:

$$(x, y) \\mapsto \\frac{y + x\\sqrt{c}}{y - x\\sqrt{c}}\$$

<br>
