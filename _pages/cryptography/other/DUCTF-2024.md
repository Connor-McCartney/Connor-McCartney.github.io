---
permalink: /cryptography/other/DUCTF-2024
title: DUCTF 2024
---


<br>
<br>


# decrypt then eval


Challenge:

```python
#!/usr/bin/env python3

from Crypto.Cipher import AES
import os

KEY = os.urandom(16)
IV = os.urandom(16)
FLAG = os.getenv('FLAG', 'DUCTF{testflag}')

def main():
    while True:
        ct = bytes.fromhex(input('ct: '))
        aes = AES.new(KEY, AES.MODE_CFB, IV, segment_size=128)
        try:
            print(eval(aes.decrypt(ct)))
        except Exception:
            print('invalid ct!')

if __name__ == '__main__':
    main()

```

<br>

Solve:

Immediately notice the weakness of a fixed IV. 

Google for an image of `aes cfb encryption diagram`

Blocks are encrypted like so:

```python
from Crypto.Cipher import AES
import os
from pwn import xor

KEY = os.urandom(16)
IV = os.urandom(16)

pt = os.urandom(1024)
ct = AES.new(KEY, AES.MODE_CFB, IV, segment_size=128).encrypt(pt)

assert ct[:16]   == xor(pt[:16], AES.new(KEY, AES.MODE_ECB).encrypt(IV))
assert ct[16:32] == xor(pt[16:32], AES.new(KEY, AES.MODE_ECB).encrypt(ct[:16]))
assert ct[32:48] == xor(pt[32:48], AES.new(KEY, AES.MODE_ECB).encrypt(ct[16:32]))
...
```

Now our goal is for the plaintext to be `b'FLAG'`

All we have to do is solve for `AES.new(KEY, AES.MODE_ECB).encrypt(IV)[:4]` using a different plaintext and we can construct our ciphertext!

Some plaintexts will throw an exception so we can start by finding a valid one of length one and append to it byte by byte. If the plaintext is just some number, then eval() won't cause any problems for us. 

<br>

```python
from pwn import *

def send(ct):
    io.recv()
    io.sendline(bytes(ct).hex().encode())
    return io.recvline()[:-1]

#io = process(["python", "decrypt-then-eval.py"])
io = remote('2024.ductf.dev', 30020)

ct = []
while len(ct) < 4:
    tmp = ct + [randint(0, 255)]
    pt = send(tmp)
    if all(i in b'123456789' for i in pt) and len(pt) == len(tmp):
        ct = tmp
        print(pt)

IV_ENC = xor(pt, ct)
forged_ct = xor(IV_ENC, b'FLAG')[:4]
print(send(forged_ct))
# DUCTF{should_have_used_authenticated_encryption!}
```


<br>

<br>

# V for Vieta


Challenge:

```python
#!/usr/bin/env python3

import os
import random
import json
from enum import Enum


FLAG = os.getenv("FLAG", "DUCTF{dummy_flag}")


class State(Enum):
    INITIAL = 1
    TEST = 2
    QUIT = 3


class Server:
    def __init__(self):
        self.level = 2048
        self.target = 2048
        self.finish = 8
        self.state = State.INITIAL

    def win(self):
        return {
            "flag": FLAG,
        }

    def generate_k(self):
        self.k = random.getrandbits(self.level) ** 2
        self.state = State.TEST
        return {
            "k": self.k,
            "level": self.level,
        }

    def test(self, challenge):
        a, b = challenge["a"], challenge["b"]
        if a <= 0 or b <= 0:
            self.state = State.QUIT
            return {"error": "Your answer must be positive!"}

        if a.bit_length() <= self.target or b.bit_length() <= self.target:
            self.state = State.QUIT
            return {"error": "Your answer is too small!"}

        num = a**2 + a * b + b**2
        denom = 2 * a * b + 1

        if num % denom != 0 or num // denom != self.k:
            self.state = State.QUIT
            return {"error": "Your answer wasn't a solution!"}

        self.level -= self.level // 5

        if self.level <= self.finish:
            self.state = State.QUIT
            return self.win()
        else:
            return self.generate_k()


def main():
    server = Server()
    print("V equals negative V plus or minus the squareroot of V squared minus 4 V V all divided by 2 V!")

    while True:
        if server.state == State.INITIAL:
            print(json.dumps(server.generate_k()))
        elif server.state == State.TEST:
            challenge = json.loads(input())
            print(json.dumps(server.test(challenge)))
        elif server.state == State.QUIT:
            exit(0)


if __name__ == "__main__":
    main()

```

<br>

Solve:


```python
from math import isqrt
from json import loads, dumps
from pwn import remote

def solve(k):
    x, y = isqrt(k), 0
    while True:
        x, y = (2*k-1)*x - y, x
        if x.bit_length() > 2048 and y.bit_length() > 2048:
            return x, y

io = remote('2024.ductf.dev', 30018)
io.recvline()
while True:
    out = io.recvline()
    if b'DUCTF{' in out:
        print(out)
        break
    k = int(loads(out)['k'])
    a, b = solve(k)
    io.sendline(dumps({'a':a, 'b':b}).encode())

# DUCTF{jump1n6_4nd_fl1pp1n6_up_7h3_hyp3r8011c_14dd3r}
```


<br>

<br>

# three line crypto


Challenge:

```python
import os, sys
q, y = os.urandom(16), 0
for x in sys.stdin.buffer.read(): sys.stdout.buffer.write(bytes([q[y % 16] ^ x])); y = x

```

<br>

Solve:

The flag format `DUCTF{` will be quite useful for us. 

Let's analyse on a random plaintext first. 


```python
import os, sys
key = os.urandom(16)
y = 0

p = b'Lorem dolor ipsum here is the flag DUCTF{fake}.'
c = b''
for x in p: 
    c += bytes([key[y % 16] ^ x])
    y = x

assert c[0] == key[0] ^ p[0]
assert c[1] == key[p[0] % 16] ^ p[1]
assert c[2] == key[p[1] % 16] ^ p[2]
assert c[3] == key[p[2] % 16] ^ p[3]
...
```


```python
flag_index = 35 # brute real one
assert c[flag_index] == key[p[flag_index-1] % 16] ^ ord('D')
assert c[flag_index+1] == key[p[flag_index] % 16] ^ ord('U')
assert c[flag_index+2] == key[p[flag_index+1] % 16] ^ ord('C')
assert c[flag_index+3] == key[p[flag_index+2] % 16] ^ ord('T')
assert c[flag_index+4] == key[p[flag_index+3] % 16] ^ ord('F')
assert c[flag_index+5] == key[p[flag_index+4] % 16] ^ ord('{')
```


```python
assert c[flag_index] == key[ord(' ') % 16] ^ ord('D')
assert c[flag_index+1] == key[ord('D') % 16] ^ ord('U')
assert c[flag_index+2] == key[ord('U') % 16] ^ ord('C')
assert c[flag_index+3] == key[ord('C') % 16] ^ ord('T')
assert c[flag_index+4] == key[ord('T') % 16] ^ ord('F')
assert c[flag_index+5] == key[ord('F') % 16] ^ ord('{')
```


Let's see if any are the same:

```python
for i in 'DUCTF{':
    print(i, ord(i)%16)
```

```
D 4  
U 5  
C 3  
T 4  
F 6  
{ 11
```

We see 'D' and 'T' have the same. 

This can help narrow down where the flag index is. 

```python
assert c[flag_index+1] == key[4] ^ ord('U')
assert c[flag_index+4] == key[4] ^ ord('F')


for find_flag_index in range(len(c)-4):
    if c[find_flag_index+1]^ord('U') == c[find_flag_index+4]^ord('F'):
        print(find_flag_index)
```


We can get 5/16 key values from the flag format:
```python
print([i for i in key])

recover_key = [0 for _ in range(16)]
recover_key[ord(' ') % 16] =  ord('D') ^ c[flag_index]
recover_key[ord('D') % 16] =  ord('U') ^ c[flag_index+1]
recover_key[ord('U') % 16] =  ord('C') ^ c[flag_index+2]
recover_key[ord('C') % 16] =  ord('T') ^ c[flag_index+3]
recover_key[ord('T') % 16] =  ord('F') ^ c[flag_index+4]
recover_key[ord('F') % 16] =  ord('{') ^ c[flag_index+5]

print(recover_key)
```


For the rest we can try some common words:



```python
c = bytes.fromhex('309c0fe5880a72faaa3d1a13c00b6e0455d0860de4c022f58814577ac9f475ef058d200e2fe5c04e109c0fe588144ec9e3e26172f42d5f200ae216b10ed1880ed61a0a762b3a8813c78213dd3c864b13c00b6e1455c6a263d0c80a72e39a91850222fc33109dd1c04e11e4cb0e75ef0f01d5d413cd200f8813c00b6e144ecd2b3cd3c57b9c0fe5881706f8cb181a01e2d0c8045be5dcc4f46378aa2b3e0ecb0cd8b108d0c8109c0fe588171587cdc48763c4ad1706e5c1c0201f8813da81c4fdb1145f3c9ee83d1a01e2d0c813c01c81c3f9d185058d2b3d01c57f4f2d524e06e38d6e0a6a8513c00b23763d1461266382122002d3e83c9b5bfdb10bf8c29c1adb30617cd14e880098fed081cad73d1bb11ec06e13c00fe5880bf42ff58813c00b6e0098f8c1c1cb0cd41ec02fe3e26dfdfecc0cd413c00b6e1451b689b12bf8c78d3cc806ff0f88245f3c8d3d1a0a7ac9f5849b65c3ad0591851ecad73cc80587d7201fd1850f01cee102204b022fe39cc04e08cc085f6e04520fff0c912aa26f520ffecc02c4ff4b06f255d0864b01e2d0c813c00b6e170be4236347109c0b2fe585762fe3c49b6dff0f880a7acb0c98f42a88109dd1c04e13c00b6e008689e10262b11ecad73cc8090e39d975e2d7200f88009dc3f9849b78c00b6e03da89e4299c1adb1a08c4ad26f2520b22fed73d01ef06ff0f881ec06e21ece420183078c782159d3d4ec1c6491a0238e83cc80ca6cb0f84b10455cf766e01e2cdd6880ed184b121ece42018306dff0f8823da91c4f5857e72f8c1db1a13c7c5913ac00b3cd3ef1ecad73cc8009dc3f9db1a2e851453cb0cda616dff0f8813c001d762b101e2d0c8109c01d15f6e03cd22f8c29c1a8813c00b6e1095e3c57b01d09b5f6e01e4d79b4ea27f4a1589ff0cd401ff87cf33022fe39cc049871a109bcf71c806e58813c0178500868d2fe58813da81c1cd201f8f871a144eda87c9aa629b620e3e13dd200e75ef06ff0f880f0fe4201fcd3cc808c4ad13c00b6e008687d4e83d16b101e2d0c8109c01cf1978c01c8d2b6e0f1b200fda8d2a88145404d5d9649c07d1cd6e0f0b27c3e83c9b1a059a87d5875f6e13c00b6e059a89faaa3d169b78c00b6e01e83c9cc1c9f46e059a89faaa3d1a08c4ad245f21d101ef06ff0f880456fed6c00b2a880ecb4b1708d5913cc49b78c01785090ae5c1d3e86e01e2d08d3d4e8806ff0f882be8c65f2fff4b0bf0e69a18169b7c06ff47b114520b3e0f0b3c8c85749bc684b101e2d09b5bfaa6cb0cd8b106e21a13c00b6e0bfed4e84463c4ad13c007cb0e6e08d59a4b2a72f4200afde43d1a0455cc184eda89f8cb181a13c00b2b62b10f0b2fe3e26dff0f880f0b22e14bb128820bfed08c8808c4ad33cd29912fb0b126ff0f8813c001d762b113c7cd8e9b617acb0e3c9eecbdb101ff87cf33109c01d15f6e0f0fff0f8813c00b6e08cef8d3e86e144a159d200ccfc56dff0f880587db8877c1d65955d4e83c8d3cc808c4ad13c00b6e044f3c9ee82a88170bfed7299c55c56dff0f84b1058d2fe381cb0cd406b11ecad7200cd40443d5158d3d491a1587cdd685663e13c7d086479b7f53c9e7ecff1e3d16b106ff0f88209bc6db1a06fdfdb106ff0f88209bc6cccd3d495f3d169b7b9c01820a72faaa6e13c00b6e01e4c022f5db1a1ecad73cc8045be38d62b10587d6c04e1ec06e109c0182091e3c9b5f4478c00b6e13cd200fcd3cc812201855d59a4b0ecb08488d2fe25f62b106ff0f8801ff87cf330f0b2fe7e820617f520b2a8808cc4b0a72ff4c871a1455d59dcb0cd413c00b6e1581c6520b3d1a08c4ad1ecad73cc81589f8cb512663c4ad109c07c6524e08cc0e6e0ed61a23fd0d6eeef6b89c0b2034cbcb34c6c7d72c9cf7da01d09cf7cbd1f7cdd73ad528c56dff0f8813c001d762b10238e8204b13c001d762b108c4ad109c01cf3310916e0ca104d5d40904d6881ec03aa27b9c0fe5880a72ff1853cacc4b08c4ad13c00b6e1451a6c03d1a14520ffdfdb10f01cef58813c00b2b6e1455cdcc479b7b9c0b3ac00b3cc813c7821095e5cb524e0885913cc80453d1c1c03d1a058d6e13c01785109dc9fdbd9b6b868d2fe588245bf43d5be3c4b106ff0f8813c78213c9faaa6e13c00b6e022fe39cc04e0ecb4b04520fe38f91629b78c00fe58814558213c00b6e0a7ac29c1ad185109bd084f5880a72e885109122f255cf766e13c00b2b4460fed08c8808c4ad0f0b3cc80ecb08488d2fe25f62b10a72e24ecd3cc808c4ad0f0b3cc813c1c8763d169b6e81cb0fc1cb0cd413c017850a7cd6c00b3ccf871a0a6ad79cc4f46e1587d7200f8813c01785059a87d5d89b63d0c806e21a13c00b6e0587d7200fc4f43d491a08c15f2fff4c871a209bc68813c001d76e0455cf76629b7f55cef46e03da8d2ff58808c4ad145f2ffc762047b113c1c9fdb101ece3c833c01b22f46e0587d5fe6e8d28e2d08d6e13c00b2b62b106ff0f8833cd3ac017d61a109dcb4b13c00b2b6e13c7820f0b3cc81455cc617b9dd1c04e06fdfdb10f0b3cc81095e7e83d1a01e2d0c803c7d5913cd3ef08d0c806e21a06b1144ec9e3e260f4200f8813c0178501ff8d3d524e058d2ffc601a08d73cc80bf0f6939dcb0cd40a7ccc1fc01d1a13c78204520b2b3cc49b7b9c0b3c8d6e4080df9ddd1a8813c00b6e2a72f8c18806ff0f8813c001d15f6e17123c9b4f27cb0cd42456f0e687306db1144a06f25f6e0ed61a08d2022002cb0ccfef145f2b6fb1158d2a88345955d0980eca85871a145f22f7876407d61a06e385601a03da89e6871a0ecb47b11ec02fbdb106ff0f880f0fe5c04e0bf428f98813c00b2b6e0a7cd08d4478c00fff4b13c0178501f822fdb10a762b2a8808c4ad0f0b2fe7e820510c058d6e109c0fe58813c001d76e109dc9e585196ae2d0c8090e27d1c00b3cc833c9e39cc9e39d3d1a0f01d2023d1a13c782045bfdfdb113c00b2b6e0ca6cb0cd89b6204d0c80a72e88514558203c1d78d6e06b10be43d4e8808c4ad1455d4e83c8d27c29a1fd1af6969913cc80bf8c29c1a88123e08cc4b13c00b2b62b10f01d587558220868d2b2d5f6e06f5c57ad78d446922e8d653d02334871a01e4c022f5db16b106ff0f88371587d15f3c980ecb0e6e0904d6880f0b2b2aa2640b3cc80a7cd6c00b3ccf871a11e2cbc65f6e02201fda8d2fe5c1cb0cd413c782158d3add3c8646197ae2d72d521d5bf7e86e06b1171587d14a023c87d73d1a11e2dbc4f69162b106ff0f8814577ac9f46e08cc4b13c007d630616a850587cef58802200fcd2fe7e2d73cc4b106ff0f88170ed1d1cccb0cd8b10238e8204b06e21a2e899b78c00b3d5f6e1708cdd0c81095e888649dc9f5cd3c8d2a88144d95f8cb1816b106e58808cc085f6e058d299dcb479b6b8687d5d413c1c87622e885123d5f2a8812201fc78213c00b6e11e2cbc65f6e08c4ad171589e8c03cc66165cb4b022fe384e885144a1581cb0cd967c1c1cd62b1109c0b204b13c00b6e0ec6438503da81d56d617622e5db1a01ff87cf3313c00b6e0a7cd7201fc9f8cb181a0f01c3e3c4b106ff0f883d493e0f17d7cf871a059a8d2fe5c06479200981cb0fdb1a13c00b6e04489d237184f8cb0cd40456fec684b10238e8204b13c00b204b4080c1d61a13c1c87675c57c158d3d491a03cd2b3e471ecad73cc8170bfed7299c4e058d2607cb0f8813c00b6e008687c3ff02cb0cd408da429b6dff0f8813cd2ff2524e13c00b6e01f83c9a87d5d9719d3c8602d6520b2a8814520fe38d6e13c782145207cb0e606178c00fe5880bf0ff0f8813c00b6e044889e7e4cb0cd401ece385763ccf871a171589e8c03cc801f822f7e4c9e2169b7b9c07c6524e13df9dc65f6e13c00b6e144f20185207cb0e62b113df9dc65f6e13c00b6e01ff87d14e880f0fe21a01e822e593c56de889b113c00fe58f871a13c00b6e0bf0ff0f88109c01d15f6e0587d7200fc4f43d491a0f0fe39ee83d4e85704887d214306e9d3c9b4e84b1145f2b6fb113c00b6e0589e386181461266e9d3a88023c8d6e08d73cc80a763ac9fdb10456f42fe7e8446dff4b122000a104d59a4b144f3c8eecf25f62b10f0b2b2a8810916e13c78201e2d08d22f42fe3866178c00b6e109dcb0fdb1a06ff0f8811ece391cccb0cd413cd2363023cc808c4ad13c00b6e1451b6899b78c00b6e0bf8cb0e2ffdb113c1c9e5c04e06ff0f880f0ff381d1db1a08c4ad13c00b6e144a08d6849b7b9c0fe5880238e83c9185158d299dcacc4b1eccc022f5db16b106ff0f88109c0fe58803cd2002c03d1461640b3c8d6e0584f8d1c00b22f8c03cc8144a1581cb0c871a13c00b6e0455d08647b106ff0f880f0b3c8d6e13c00b6e008689e102629b78c00b3c8d6e022fe39cc04e0ed61a00868d2b204b109dd1c04e13cd200fcd3cc8008687d580c04e08c4ad13da8d2b3d306dff0f88008689e2491a12200981c1cccd20454b345f2b6e0f01d5d401ff87cf3333c57ccee43d1a0455cf763d3078c00b6e145bf7ebff87cc4c871a01ff89f68689ff085f62b10ed3e2d0918501ff87cf332ecb0f849b6aff87cf33345bf389b6871a10912ffaa3f8cb0cd41455cc181a13c00b27d7c801ff89ff00a6cb085f20185f629b65d787cc4b01ff87cf3313c00b6e090afaaa2a8824520ffde8c79b16b1045be24ec7d0c81589ff00c56aff87cf333708cc1fdd3d16b101ff87cf33223e0ed79d3d1a13c00b6e171581df49636306fdfc60306385d413c00b6e0a72e38d3d1a08c4ad2222f8d614617f4f2d524e13c00b6e023acd3c860afdb10587cc0fa26dff0f88144f2d524e13c00b6e0bf0e6871a059185290ae5dd3c8d69871a0f0fff0f880ec86308d15f2aa263cc4b0456f8c8766e06ff0f880456f8c87662b10269913cc81453cb085f6e13c00b6e171581c872fdb103c9e69a617b9c0b204b08cef58823cd3b2d5bfdf8cacc4b08cc4b13c00b6e12201b0221d20bf42a88022fe39cc0646f5be24e88144ec7cc0e3d16b1109c0b20085f6e0a762047b106b101e1f8cb1fd1851589f25f62b110913c8d6e158d2fe38d2a8661793e4713c00b204ab10ec3ad01ece58813c00b6e1455cbc9bdb10bf43a88144edd3c8cd185059d22fde230793e13dd3c864b0ed18801ff87cf3313c00b6e1ec02fe3cf871a01e4d79b4e8808d2022002cb0cd40a7ccc1fc01d169b6dff0f880bf43a8813c00b6e0456fec6db1a0bf8c06e0589e38d6e13c1c9fdb10589faaa2a8813c78203dd3d4ea26e918513c00b6e1581d5026e144f20181a08c4ad144f237e763cd3ef059d3a880ec3ad13c00b6e022fe39cc06460f43d491a01ff9d27d1cef822b10d593d4e88023c8d6e26e38b4edd3c9d3d1a1581d65f447b9dd1c04e14520ffdfdfed5913cc813da8d2008524e123e13c1c9e5880ed185334080df9dc9fdb1144f28ebe4c65f75c578c00b3c8d62b10bf43d4e8810912b2adb1a045201c9aa6e13c00b6e044887d240871a0be4361b3c81c4ff085f62b10f0b3c8d629b60f43d4e8813c00b6e14595bff1f880a7ccbd64edd3c8d6e01ecf8c9b113c00b6e0589e39a8d204b145bff0f866178c00b204b13c001d76e14520ffde588144f28ebe83cc80ecb4b06fde5cd3c860ae5cd6e1ec02fe39b3078c00b6e090e39d9618d2fe1022a8801e4c022f5db1a13c782158d3d4e84b106ff0f8808cc4b13c00b6e170bf0f8cb616db104489d3d4e8808c4ad1456fed6c04e13c7820f0fe38ccd2050ef08d0c4b1109c0b204b144ec9e39b306de38d6e04520fff0c912a880ecb4b0f0b2fe7e82047b113c00b3c8d6e1455d5d413c00b6e009bcef5cd204b008689f8cb617b9c0b3c8d6e023c9b4e84b10be4361b3c81c4ff1f88109dd1c04e0ed1db1a16e427d3e83c81cb0cd41708c6849b7c1222e25f62b108d0c813c00b6e1456f4200fcd3cc811e83acb5243704887d24bb113c001d76e0f0fe24e880456f42fe38d2a849b6dff0f880be43e0ecb4b1455d73cc4b1109c01d15f6e059a81d1dcc4f46e144ec9fdfabc1a06e381d65f629b6db10f1b3c9cc4f8cb0cd401e2d08d3d4e864b21e2d0c813c00b6e170bf0f8cb4b0ed61a1706e38b520b2aa26e918501e1f0e943704887d24bb11706e38b520b2a8805918508c3e5db16b10591851708d2170ec03d1a1706e38b520b2aa265cb4b2bf43ac00b636056e423718d3cc803da8d2008520b2a864b290ae5c002f43d491a05918504520fff0c914478c00b6e13da89e7ecf8c9f8cb0cd4022fe39cc04e0ed61a0bf8c29c1acd200e2a84b1059d3a88144ec1cb1f880904d6a27b9dd1c04e158d28f83d5f6e1581c6524e13c7821455c3faef13c00b6e13c007d79b4ed1851455cbc9bd9b6dff0f88145201d5913cc801e2d722b106e2520b3d1a0885913cc813c00b6e0236060fe43d4ecd2a8801e4c022f5db146178c01b3d1a0591851587d6c9e5c1cacc4b0bf8ceaa6e158d3e08d15f6e0ed61a0095f8cb0e2a849b6204d0c8022fe39cc04e0a762fff1c9c07c9f46e12200e2fe38d2a8806ff0f8813c00fff00a3f43d491a0bf428f9866163c4f984b113c7cd8eb14080df9dc9fdb10587cdd68813c78201e4d78d6e13c00b6e090afaaa2a8801e4c022f5db169b6dff0f8813c00b6e0bf8c29c1a88144edd2c8a84f46e059d3c864b109dd1c04e044889f251a3f8cb0cd401e1f0fc763d01c57b9c0b3ac00b3cc813c00fe588022fe39cc04e13c00b3c8d28ff87cf331455cf766e0f07c1cccd204b144eda8d200c80c0646dff0f8801ece5dccd2002cb0cd401e2cdc68803cd3c81d3e83d16b108d0c813c00fe58813c00b6e01e4d78d446e89faaa3d1a0238e83c91850584f4237ad6524e08d73a84b106ff0f88144d912fe5db1a06e695e8af692ff2524e123d5f22f43d491a0f1b237cd73cc4b108d0c813c00fe58813c00b6e0f0b2fe588122007fec151bc30620e39d41706e2495bf6913d1a06ff0f88145f2d488d3a881708d08d3d16b1109c0b3c8d2c91af78c00b27d7c80bf8c3e863795927c65f6e13c78213c00b6e13cd200fcd3cc80584f0f5cd3d1a0a72e885109dcb50c563d0c813c00fe5880ed1880f0fe38ccd20181a0a7cd08d6e06ff0f880f0b22e1141a13c7820581cb0fa278c00b6e0095e10ecb0cd411e827cb1816b10bf43d4e881702200e3ada89e5c1cb0cd4145201d5913c9b169b63d0c801e4c03c8b5f6e144f204c871a1589e7e82002cb0cd40a7ac29c1a84b108d0c8145f2fe38b5207cb0cd40584f0e24ea263c4ad13c00b6e0caa2b204b0904d09cc04e145201d722f588145f2fe3c813c00b233d4b309122fdbdb12e85109bd6849b640b6e145f3c9ee83d1a13c00b6e01e4c022f5db1a109c0182109dd1c04e0f07d61a0f0fe39a87d5d4059a8d2ffabc3078c00b6e1456e429939dd6524e0456fec6db16b106ff0f880f1b3c8cc4f43d1a08d153c03cc567df9dcb0e2aa2640ffdf43d1a0885913cc813c00b2328ef01ff87cf3313c00b6e01ece3c828cee8c8630ec4ff4b0f0b27c29c1aa26407c833009bcef5cd204b245f3c8d3d1a0904d6880ecb4b11ecf8cb4b158d2995e38cdb01c56dff0f880f0b62b1109c01820f0fe7e4cb0cd4170bfed7299c0b2a8813c00b6e01ecfdfdfed5d4170bf0f8cb616dff0f880f0b2fe7e82a880ed1db1a01f83c9a87d58d851581c1cf913d16b113dd3c86181a08cc085f6e0a7cd08d446f4887d14917649dd65f6e0f07d61a14520fe5dccd3c81cb0cd414520fe38d62b1109dd1c04e144eda87c9aa6e08cc4b144eda87c9aa4478c00b6e022fe39cc04e06e2495bf8c9e216b106ff0f880a72faaa3d1a13c00b6e01e4c022f5880f07d61a13c01c89fdfdbf')
recover_key = [0 for _ in range(16)]

flag_index = 1333
recover_key[ord(' ') % 16] =  ord('D') ^ c[flag_index]
recover_key[ord('D') % 16] =  ord('U') ^ c[flag_index+1]
recover_key[ord('U') % 16] =  ord('C') ^ c[flag_index+2]
recover_key[ord('C') % 16] =  ord('T') ^ c[flag_index+3]
recover_key[ord('T') % 16] =  ord('F') ^ c[flag_index+4]
recover_key[ord('F') % 16] =  ord('{') ^ c[flag_index+5]

for word in [b' the ', b' of ', b' and ', b' to ', b' a ', b' is ', b' for ', b' in ', b' on ', b' that ', b' by ', b' this ', b' with ', b' you ', b' it ', b' not ', b' or ', b' be ', b' are ', b' from ', b' at ', b' as ', b' your ', b' all ', b' have ', b' an ', b' was ', b' we ', b' will ', b' can ', b' about ', b' if ', b' my ', b' has ', b' free ', b' but ', b' our ', b' one ', b' other ', b' do ', b' no ', b' time ', b' they ', b' he ', b' up ', b' may ', b' what ', b' which ', b' their ', b' out ', b' use ', b' any ', b' there ', b' see ', b' only ', b' so ', b' his ', b' when ', b' here ', b' who ', b' also ', b' now ', b' get ' b' first ', b' am ', b' been ', b' would ', b' how ', b' were ', b' some ', b' these ', b' like ', b' than ']:
    for idx in range(len(c)-4):
        valid = True
        for i in range(len(word)-1):
            if recover_key[word[i]%16] != 0:
                if recover_key[word[i]%16] != word[i+1] ^ c[idx+i]:
                    valid = False
                    break
        if valid:
            for i in range(len(word)-1):
                if recover_key[word[i]%16] == 0:
                    recover_key[word[i]%16] = word[i+1] ^ c[idx+i]

recover_key[10] = 44
# recover_key = [103, 145, 232, 58, 168, 78, 141, 244, 110, 165, 44, 207, 145, 19, 107, 162]



y = 0
p = b''
for x in c:
    d = recover_key[y % 16] ^ x
    p += bytes([d])
    y = d
print(p.decode())
```


```
What makes the cornfield smile; beneath what star  
Maecenas, it is meet to turn the sod  
Or marry elm with vine; how tend the steer;  
What pains for cattle-keeping, or what proof  
Of patient trial serves for thrifty bees;  
Such are my themes.  
  
O universal lights  
Most glorious! ye that lead the gliding year  
Along the sky, Liber and Ceres mild,  
If by your bounty holpen earth once changed  
Chaonian acorn for the plump wheat-ear,  
And mingled with the grape, your new-found gift,  
The draughts of Achelous; and ye Fauns  
To rustics ever kind, come foot it, Fauns  
And Dryad-maids together; your gifts I sing.  
And thou, for whose delight the war-horse first  
Sprang from earth's womb at thy great trident's stroke,  
Neptune; and haunter of the groves, for whom  
Three hundred snow-white heifers browse the brakes,  
The fertile brakes of Ceos; and clothed in power,  
Thy native forest and Lycean lawns,  
Pan, shepherd-god, forsaking, as the love  
Of thine own Maenalus constrains thee, hear  
And help, O lord of Tegea! And thou, too,  
Minerva, from whose hand the olive sprung;  
And boy-discoverer of the curved plough;  
And, bearing a young cypress root-uptorn,  
Silvanus, and Gods all and Goddesses,  
Who make the fields your care, both ye who nurse  
The tender unsown increase, and from heaven  
Shed on man's sowing the riches of your rain:  
Of which one is DUCTF{when_in_doubt_xort_it_out};  
And thou, even thou, of whom we know not yet  
What mansion of the skies shall hold thee soon,  
Whether to watch o'er cities be thy will,  
Great Caesar, and to take the earth in charge,  
That so the mighty world may welcome thee  
Lord of her increase, master of her times,  
Binding thy mother's myrtle round thy brow,  
Or as the boundless ocean's God thou come,  
Sole dread of seamen, till far Thule bow  
Before thee, and Tethys win thee to her son  
With all her waves for dower; or as a star  
Lend thy fresh beams our lagging months to cheer,  
Where 'twixt the Maid and those pursuing Claws  
A space is opening; see! red Scorpio's self  
His arms draws in, yea, and hath left thee more  
Than thy full meed of heaven: be what thou wilt-  
For neither Tartarus hopes to call thee king,  
Nor may so dire a lust of sovereignty  
E'er light upon thee, howso Greece admire  
Elysium's fields, and Proserpine not heed  
Her mother's voice entreating to return-  
Vouchsafe a prosperous voyage, and smile on this  
My bold endeavour, and pitying, even as I,  
These poor way-wildered swains, at once begin,  
Grow timely used unto the voice of prayer.  
In early spring-tide, when the icy drip  
Melts from the mountains hoar, and Zephyr's breath  
Unbinds the crumbling clod, even then 'tis time;  
Press deep your plough behind the groaning ox,  
And teach the furrow-burnished share to shine.  
That land the craving farmer's prayer fulfils,  
Which twice the sunshine, twice the frost has felt;  
Ay, that's the land whose boundless harvest-crops  
Burst, see! the barns.  
  
But ere our metal cleave  
An unknown surface, heed we to forelearn  
The winds and varying temper of the sky,  
The lineal tilth and habits of the spot,  
What every region yields, and what denies.  
Here blithelier springs the corn, and here the grape,  
There earth is green with tender growth of trees  
And grass unbidden. See how from Tmolus comes  
The saffron's fragrance, ivory from Ind,  
From Saba's weakling sons their frankincense,  
Iron from the naked Chalybs, castor rank  
From Pontus, from Epirus the prize-palms  
O' the mares of Elis.  
Such the eternal bond  
And such the laws by Nature's hand imposed  
On clime and clime, e'er since the primal dawn  
When old Deucalion on the unpeopled earth  
Cast stones, whence men, a flinty race, were reared.  
Up then! if fat the soil, let sturdy bulls  
Upturn it from the year's first opening months,  
And let the clods lie bare till baked to dust  
By the ripe suns of summer; but if the earth  
Less fruitful just ere Arcturus rise  
With shallower trench uptilt it- 'twill suffice;  
There, lest weeds choke the crop's luxuriance, here,  
Lest the scant moisture fail the barren sand.  
Then thou shalt suffer in alternate years  
The new-reaped fields to rest, and on the plain  
A crust of sloth to harden; or, when stars  
Are changed in heaven, there sow the golden grain  
Where erst, luxuriant with its quivering pod,  
Pulse, or the slender vetch-crop, thou hast cleared,  
And lupin sour, whose brittle stalks arise,  
A hurtling forest. For the plain is parched  
By flax-crop, parched by oats, by poppies parched  
In Lethe-slumber drenched. Nathless by change  
The travailing earth is lightened, but stint not  
With refuse rich to soak the thirsty soil,  
And shower foul ashes o'er the exhausted fields.  
Thus by rotation like repose is gained,  
Nor earth meanwhile uneared and thankless left.  
Oft, too, 'twill boot to fire the naked fields,  
And the light stubble burn with crackling flames;  
Whether that earth therefrom some hidden strength  
And fattening food derives, or that the fire  
Bakes every blemish out, and sweats away  
Each useless humour, or that the heat unlocks  
New passages and secret pores, whereby  
Their life-juice to the tender blades may win;  
Or that it hardens more and helps to bind  
The gaping veins, lest penetrating showers,  
Or fierce sun's ravening might, or searching blast  
Of the keen north should sear them. Well, I wot,  
He serves the fields who with his harrow breaks  
The sluggish clods, and hurdles osier-twined  
Hales o'er them; from the far Olympian height  
Him golden Ceres not in vain regards;  
And he, who having ploughed the fallow plain  
And heaved its furrowy ridges, turns once more  
Cross-wise his shattering share, with stroke on stroke  
The earth assails, and makes the field his thrall.
```
