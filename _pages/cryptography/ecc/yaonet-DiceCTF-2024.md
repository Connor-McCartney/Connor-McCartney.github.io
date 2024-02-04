---
permalink: /cryptography/ecc/yaonet-DiceCTF-2024
title: yaonet - DiceCTF 2024
---

<br>

[Challenge files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2024/DiceCTF/yaonet)

<br>

Given pub:

```
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHvYGqk903tU4dOcBPTbZ9xl5rlSEQfdEcgOhx7zvWFLGhetWlG2zHUXYYiBcCoj/ozG5LsGrzpcXE3HuEzPEQg= yaonet
```

Given (corrupted) priv:

```
-----BEGIN OPENSSH PRIVATE KEY-----
??????????1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAA????????????????????????
??????????c3RwMjU2AAAACG5pc3RwMjU2AAAAQQR72Bqp????????????????????????
??????????1hSxoXrVpRtsx1F2GIgXAqI/6MxuS7Bq86XF????????????????????????
??????????ZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAy????????????????????????
??????????lSEQfdEcgOhx7zvWFLGhetWlG2zHUXYYiBcC????????????????????????
??????????37PMrof3dNCpeuwsSUupbaUh3/+7+eDnRH+3????????????????????????
-----END OPENSSH PRIVATE KEY-----
```


We can assume these keys were generated with the command `ssh-keygen -t ecdsa`, <br>
and can use this to generate some dummy keys to analyse. 


```
[~/Desktop] 
$ ssh-keygen -t ecdsa
Generating public/private ecdsa key pair.
Enter file in which to save the key (/home/connor/.ssh/id_ecdsa): dummy
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in dummy
Your public key has been saved in dummy.pub
The key fingerprint is:
SHA256:nRYzmNhjhxIz0WWrYnSt/T80dVqI6g0+GlfVjn6cV0k connor@arch
The key's randomart image is:
+---[ECDSA 256]---+
|      =o .o      |
|       *.* .   . |
|      + O B  ..E.|
|     . + B =..oo=|
|      o S =.. .=+|
|     . . .oo .+.o|
|        .o.o...o+|
|         o+ .....|
|        .. .  .. |
+----[SHA256]-----+

[~/Desktop] 
$ cat dummy
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRKibaLbkv3KDTKOB6F/Ahw8aftqvLf
Mv+TKGmLJNOKnaQCNfNAje+5k2GwcWgNDsNUqTzGAGn0/TKkQJlXgOqpAAAAqAHhCzIB4Q
syAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEqJtotuS/coNMo4
HoX8CHDxp+2q8t8y/5MoaYsk04qdpAI180CN77mTYbBxaA0Ow1SpPMYAafT9MqRAmVeA6q
kAAAAhAIb+GFaE9rBXwNwhzYx6ICk+Kd/x5XkXUxBPrmisqTuyAAAAC2Nvbm5vckBhcmNo
AQIDBA==
-----END OPENSSH PRIVATE KEY-----

[~/Desktop] 
$ cat dummy.pub 
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEqJtotuS/coNMo4HoX8CHDxp+2q8t8y/5MoaYsk04qdpAI180CN77mTYbBxaA0Ow1SpPMYAafT9MqRAmVeA6qk= connor@arch
```

`ssh-keygen -p -f filename -m pem` to convert the privkey from openssh format to pem format:

```
[~/Desktop] 
$ ssh-keygen -p -f dummy -m pem
Key has comment 'connor@arch'
Enter new passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved with the new passphrase.

[~/Desktop] 
$ cat dummy
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIb+GFaE9rBXwNwhzYx6ICk+Kd/x5XkXUxBPrmisqTuyoAoGCCqGSM49
AwEHoUQDQgAESom2i25L9yg0yjgehfwIcPGn7ary3zL/kyhpiyTTip2kAjXzQI3v
uZNhsHFoDQ7DVKk8xgBp9P0ypECZV4DqqQ==
-----END EC PRIVATE KEY-----
```

We can read the pem key with python now:

```python
from Crypto.PublicKey import ECC
print(ECC.import_key(open("dummy").read(), passphrase=None))
```

```
EccKey(curve='NIST P-256', point_x=33714468719919656469393613774985627418693283622155523355284522382354535385757, point_y=74183213212407040404873950700696608789162540316055855690953008810264702806697, d=61058868839081846412682869945227768869718126500541418541339379651273527212978)
```

And convert to hex:

```python
point_x = 33714468719919656469393613774985627418693283622155523355284522382354535385757
point_y = 74183213212407040404873950700696608789162540316055855690953008810264702806697
d = 61058868839081846412682869945227768869718126500541418541339379651273527212978
print(f"{point_x:x}{point_y:x}")
print(f"{d:x}")
```

```
4a89b68b6e4bf72834ca381e85fc0870f1a7edaaf2df32ff9328698b24d38a9da40235f3408defb99361b071680d0ec354a93cc60069f4fd32a440995780eaa9
86fe185684f6b057c0dc21cd8c7a20293e29dff1e5791753104fae68aca93bb2
```

Then if we convert our dummy priv and pub key to hex we can see those values^ in them:

<br>

![image](https://gist.github.com/assets/89777327/a3e3b0a9-6aaf-432d-94f0-1de5a679a793)

<br>

In fact, we can see the entire pubkey in the privkey (twice):

<br>

![image](https://gist.github.com/assets/89777327/7b740540-bb0e-4c9b-9652-8cd4d92a824e)

<br>

Armed with this knowledge, let's try fix the corrupted key from the challenge.

First we can convert the pub directly to hex and know it will appear twice in the priv:

```
0000001365636473612d736861322d6e69737470323536000000086e6973747032353600000041047bd81aa93dd37b54e1d39c04f4db67dc65e6b9521107dd11c80e871ef3bd614b1a17ad5a51b6cc7517618881702a23fe8cc6e4bb06af3a5c5c4dc7b84ccf1108
```

For the priv I replaced all the '?'s with '/'s before converting to hex:

```python
for line in open("id_ecdsa").readlines()[1:-1]:
    print(line.strip().replace('?', '/'))
```

Then all the long strings of 'f's are the unknowns:

```
fffffffffffffffd6b65792d763100000000046e6f6e65000000046e6f6e650000000fffffffffffffffffffffffffffffffffffffffffffffffffff737470323536000000086e6973747032353600000041047bd81aa9fffffffffffffffffffffffffffffffffffffffffffffffffffd614b1a17ad5a51b6cc7517618881702a23fe8cc6e4bb06af3a5c5fffffffffffffffffffffffffffffffffffffffffffffffffff6473612d736861322d6e69737470323536000000086e6973747032fffffffffffffffffffffffffffffffffffffffffffffffffff9521107dd11c80e871ef3bd614b1a17ad5a51b6cc7517618881702fffffffffffffffffffffffffffffffffffffffffffffffffffdfb3ccae87f774d0a97aec2c494ba96da521dfffbbf9e0e7447fb7ffffffffffffffffffffffffffffffffffff
```

Finding where the two pubkeys slot in:

```
fffffffffffffffd6b65792d763100000000046e6f6e65000000046e6f6e650000000fffffffffffffffffffffffffffffffffffffffffffffffffff737470323536000000086e6973747032353600000041047bd81aa9fffffffffffffffffffffffffffffffffffffffffffffffffffd614b1a17ad5a51b6cc7517618881702a23fe8cc6e4bb06af3a5c5fffffffffffffffffffffffffffffffffffffffffffffffffff6473612d736861322d6e69737470323536000000086e6973747032fffffffffffffffffffffffffffffffffffffffffffffffffff9521107dd11c80e871ef3bd614b1a17ad5a51b6cc7517618881702fffffffffffffffffffffffffffffffffffffffffffffffffffdfb3ccae87f774d0a97aec2c494ba96da521dfffbbf9e0e7447fb7ffffffffffffffffffffffffffffffffffff
                                                                                      0000001365636473612d736861322d6e69737470323536000000086e6973747032353600000041047bd81aa93dd37b54e1d39c04f4db67dc65e6b9521107dd11c80e871ef3bd614b1a17ad5a51b6cc7517618881702a23fe8cc6e4bb06af3a5c5c4dc7b84ccf1108                        0000001365636473612d736861322d6e69737470323536000000086e6973747032353600000041047bd81aa93dd37b54e1d39c04f4db67dc65e6b9521107dd11c80e871ef3bd614b1a17ad5a51b6cc7517618881702a23fe8cc6e4bb06af3a5c5c4dc7b84ccf1108

```


We can also add the header `00000020` immediately after the second pubkey, and then the following 64 hex chars should represent d.

```
fffffffffffffffd6b65792d763100000000046e6f6e65000000046e6f6e650000000fffffffffffffffffffffffffffffffffffffffffffffffffff737470323536000000086e6973747032353600000041047bd81aa9fffffffffffffffffffffffffffffffffffffffffffffffffffd614b1a17ad5a51b6cc7517618881702a23fe8cc6e4bb06af3a5c5fffffffffffffffffffffffffffffffffffffffffffffffffff6473612d736861322d6e69737470323536000000086e6973747032fffffffffffffffffffffffffffffffffffffffffffffffffff9521107dd11c80e871ef3bd614b1a17ad5a51b6cc7517618881702fffffffffffffffffffffffffffffffffffffffffffffffffffdfb3ccae87f774d0a97aec2c494ba96da521dfffbbf9e0e7447fb7ffffffffffffffffffffffffffffffffffff
                                                                                      0000001365636473612d736861322d6e69737470323536000000086e6973747032353600000041047bd81aa93dd37b54e1d39c04f4db67dc65e6b9521107dd11c80e871ef3bd614b1a17ad5a51b6cc7517618881702a23fe8cc6e4bb06af3a5c5c4dc7b84ccf1108                        0000001365636473612d736861322d6e69737470323536000000086e6973747032353600000041047bd81aa93dd37b54e1d39c04f4db67dc65e6b9521107dd11c80e871ef3bd614b1a17ad5a51b6cc7517618881702a23fe8cc6e4bb06af3a5c5c4dc7b84ccf110800000020
```

Giving us:

```
d = ??????dfb3ccae87f774d0a97aec2c494ba96da521dfffbbf9e0e7447fb7????
```


We can brute the rest with a MITM attack, checking if `d*G=pub`:


```python
from fastecdsa.curve import Curve
from fastecdsa.point import Point
from tqdm import trange

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
pub = (56016303349880948431599386307348858125916082976315959318890317721034119012683, 11801967982773518381246130798034965606281271763120498603562501330146719371528)
nistp256 = Curve('mycurve',p,a,b,q,G[0],G[1])
G = Point(G[0], G[1], curve=nistp256)
pub = Point(pub[0], pub[1], curve=nistp256)
known = 0xdfb3ccae87f774d0a97aec2c494ba96da521dfffbbf9e0e7447fb70000

table = {}
start_pt = int(known) * G
to_add = G
for x in trange(16^4):
    table[(start_pt.x, start_pt.y)] = x
    start_pt += to_add

end_pt = pub
to_sub = int(16^(64-6)) * G
for y in trange(16^6):
    if (end_pt.x, end_pt.y) in table:
        d = known + table[(end_pt.x, end_pt.y)] + y * 16^(64-6)
        assert int(d)*G == pub
        print(f'{d = }')
        break
    end_pt -= to_sub
```

<br>

Now reconstructing the key and using it:

<br>

```
[~] 
$ python
Python 3.11.6 (main, Nov 14 2023, 09:36:21) [GCC 13.2.1 20230801] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from Crypto.PublicKey.ECC import EccKey
>>> d = 0x455389dfb3ccae87f774d0a97aec2c494ba96da521dfffbbf9e0e7447fb7c9fe
>>> key = EccKey(curve='p256', d=d).export_key(format='PEM')
>>> open("fixed_key", "w").write(key)
240
>>> 

[~] 
$ chmod 600 fixed_key 

[~] 
$ ssh-keygen -p -f fixed_key 
Enter new passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved with the new passphrase.

[~] 
$ cat fixed_key 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQR72BqpPdN7VOHTnAT022fcZea5UhEH
3RHIDoce871hSxoXrVpRtsx1F2GIgXAqI/6MxuS7Bq86XFxNx7hMzxEIAAAAmAG5C8IBuQ
vCAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHvYGqk903tU4dOc
BPTbZ9xl5rlSEQfdEcgOhx7zvWFLGhetWlG2zHUXYYiBcCoj/ozG5LsGrzpcXE3HuEzPEQ
gAAAAgRVOJ37PMrof3dNCpeuwsSUupbaUh3/+7+eDnRH+3yf4AAAAA
-----END OPENSSH PRIVATE KEY-----

[~] 
$ ssh yaonet@mc.ax -p 31000 -i fixed_key 
The authenticity of host '[mc.ax]:31000 ([35.243.200.149]:31000)' can't be established.
RSA key fingerprint is SHA256:2O1kP6RTiXELguEHw4aC32UomxKG+vFgz/HRkMl444c.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[mc.ax]:31000' (RSA) to the list of known hosts.
dice{now_can_you_sing_it?}
Connection to mc.ax closed by remote host.
Connection to mc.ax closed.
```
