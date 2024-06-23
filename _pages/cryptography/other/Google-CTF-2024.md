---
permalink: /cryptography/other/Google-CTF-2024
title: Google CTF 2024
---


<br>

# ZKPOK (Author: Mystiz)

Challenge:

```python
import hashlib
import json
from math import gcd

# param.py is created by generated.py. Run that locally to generate parameters :)
from param import n as n0, c as c0

def hash(s):
    m = b''
    for si in s:
        sib = int.to_bytes(si, (int(si).bit_length()+7)//8, 'big')
        sil = int.to_bytes(len(sib), 2, 'big')
        m += sil
        m += sib
    return hashlib.md5(m).digest()

def verify(n, c, proof):
    s = proof.get('s')
    z = proof.get('z')
    h = int.from_bytes(hash(s), 'big')
    b = [(h>>i)&1 for i in range(127, -1, -1)]
    if len(s) != 128: return False
    if len(z) != 128: return False
    if len(b) != 128: return False

    for si, zi, bi in zip(s, z, b):
        if gcd(si, n) != 1: return False
        if pow(zi, 2, n) != si * pow(c, bi, n) % n: return False
    return True


def main():
    print('Send me your proof.')
    proof = json.loads(input('> '))
    n = proof.get('n')
    c = proof.get('c')

    if not verify(n, c, proof):
        print('BAD.')
    elif n != n0 or c != c0:
        print("I am convinced that you have m such that m^2 = c (mod n). What's next?")
    else:
        with open('message.txt', 'r') as f:
            message = f.read().strip()
        print(message)


if __name__ == '__main__':
    main()
```

<br>

```python
import re
from Crypto.Util.number import getPrime as get_prime

def main():
    p, q = [get_prime(1024) for _ in range(2)]

    with open('message.txt', 'rb') as f:
        message = f.read()
    
    m = int.from_bytes(message, 'big')


    # Encrypts the flag using the Rabin cryptosystem
    n = p * q
    c = pow(m, 2, n)

    # Sanity check: I should not...
    assert re.search(rb'CTF{.*}', message) # ...forget the flag :)
    assert m**2 >= n # ...make m so small that someone could retrieve m by computing sqrt(c).

    with open('param.py', 'w') as f:
        f.write(f'{n = }\n')
        f.write(f'{c = }\n')
    
if __name__ == '__main__':
    main()
```

```
n = 24171281203618227646148614093741897893680590469429862763616651018126182178291141461695534191580515360668625075973491504098523699503259361006971705744958883528932688017993492125655911982492437672677101525815537367543196148286955989998259443227022039948657202846637063972174783694852385201871764707353023520121014358038502097164099583969032343493472077089224564347272106493231739328199151912917075676958849850365616848259436125246050967067344589874063605862103771405549833253395136355961700736614256786908493838913193974834129994601312274562117378906031845836444184578865241200802323432200853511029948808442048002259291
c = 23600182227273910099358133594372912582919773199179273829828839557230117943609831825595573879341287133068072066324938879830422663107123488440813527886386741421937058370424389567240063193684312982625133480552982946713492184295067725675638844460661211302254449106480853610767961560376504492963755391502378330793274144402415466915344455650158737984908963924569120855971997414861671220011328054765928819282790122661223003302402664231552404933606540838530514595095462530045601820409339363585308908617319725609553274552355183460158759550133568592098227630339064730597534042467707370525507516032057789381741420573605038396418
```

<br>

Solve:

There seems to be nothing suspicious in generate.py

They make us send n and c but that's kinda redundant, we don't get any choice we have to send the same n and c provided to us. 

We can choose any length 128 array for s and z though. 

```python
    for si, zi, bi in zip(s, z, b):
        if gcd(si, n) != 1: return False
        if pow(zi, 2, n) != si * pow(c, bi, n) % n: return False
```

Every bi is either 0 or 1. 

If bi is 0 we have to have some `zi` and `si = pow(zi, 2, n)`

Else if bi is 1 we have to have some `zi` and `si = pow(zi, 2, n) * pow(c, -1, n) % n`

But note that b depends on s and the suspicious hash function. 

---

If we try to find an si that can be the same regardless of bi, we see,

`si = pow(zi, 2, n) = pow(zi, 2, n) * pow(c, -1, n) % n`

`si*c = si mod n`

The only solution is si=0. 

But, `if gcd(si, n) != 1: return False` prevents us from using this solution...

---



https://mystiz.hk/posts/2024/2024-06-24-google-ctf-2/
