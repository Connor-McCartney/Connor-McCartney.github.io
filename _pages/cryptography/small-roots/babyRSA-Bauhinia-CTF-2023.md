---
permalink: /cryptography/small-roots/babyRSA-Bauhinia-CTF-2023
title: grhkm's babyRSA - Bauhinia CTF 2023
---

<br>


Challenge:

<br>

```python
from math import gcd
from Crypto.Util.number import getPrime, getRandomNBitInteger, bytes_to_long
from secret import flag

lcm = lambda u, v: u*v//gcd(u, v)

bits = 1024
given = bits // 5
e_bits = bits // 12

mask = (1 << given) - 1

while True:
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    N = p * q

    if N.bit_length() != bits:
        continue

    l = lcm(p - 1, q - 1)
    e = getRandomNBitInteger(e_bits)

    if gcd(e, l) > 1:
        continue

    d = pow(e, -1, l)

    dp = int(d % (p - 1))
    dq = int(d % (q - 1))

    break

l_dp = dp & mask
l_dq = dq & mask

print(f'{N = }')
print(f'{e = }')
print(f'{l_dp = }')
print(f'{l_dq = }')

flag = bytes_to_long(flag)

ct = pow(flag, e, N)
print(f'{ct = }')
```

<br>

```python
N = 96446191626393604009054111437713980755082681332020571709789032122186639773874753631630024642568257679734714430483780317122960230235124140242511126339536047435591010087751700582288534654352742251068909342986464462021206713195415006300821397979265537607226612724482984235104418995222711966835565604156795231519
e = 21859725745573183363159471
l_dp = 5170537512721293911585823686902506016823042591640808668431139
l_dq = 2408746727412251844978232811750068549680507130361329347219033
ct = 22853109242583772933543238072263595310890230858387007784810842667331395014960179858797539466440641309211418058958036988227478000761691182791858340813236991362094115499207490244816520864518250964829219489326391061014660200164748055767774506872271950966288147838511905213624426774660425957155313284952800718636
```


<br><br>

Solve:

Coming soon...

![image](https://media.tenor.com/q0Ejci9EQhcAAAAi/rick-astley-rick-roll.gif)
