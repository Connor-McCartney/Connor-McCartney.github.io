---
permalink: /cryptography/other/b01lers-CTF-2024
title: b01lers CTF 2024
---

<br>


[Challenge Files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2024/b01lersCTF)


# catch-me-if-you-can

Grab source:

```
wget https://github.com/Connor-McCartney/CTF_Files/raw/main/2024/b01lersCTF/catch-me-if-you-can/chal.pyc
```

Note the first bytes 6f0d:

```
$ xxd chal.pyc | head
00000000: 6f0d 0d0a 0000 0000 6be3 1366 7118 0000  o.......k..fq...
```

Convert to decimal (little endian)

```python
>>> 0x0d6f
3439
```

Search this number to see which python version the bytecode was compiled on:

<https://github.com/python/cpython/blob/8fc953f606cae5545a4d766dc3031316646b014a/Lib/importlib/_bootstrap_external.py#L369>

```
#     Python 3.10b1 3439 (Add ROT_N)
```

Now 3.10b1 isn't a real version but we found the magic number 3439 here in 3.10.14

<https://github.com/python/cpython/blob/v3.10.14/Lib/importlib/_bootstrap_external.py#L364>

Install pyenv:

```
paru -S pyenv
```

pyenv didn't have 3.10.14 so I installed the closest, 3.10.13 (takes a little while):

```
$ pyenv install 3.10.13
Downloading Python-3.10.13.tar.xz...
-> https://www.python.org/ftp/python/3.10.13/Python-3.10.13.tar.xz
Installing Python-3.10.13...
Installed Python-3.10.13 to /home/connor/.pyenv/versions/3.10.13
```

Alias for convenience:

```
[~/Desktop] 
$ alias py=/home/connor/.pyenv/versions/3.10.13/bin/python

[~/Desktop] 
$ py
Python 3.10.13 (main, Apr 15 2024, 02:46:57) [GCC 13.2.1 20230801] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 
```

```python
import dis

with open("chal.pyc", "rb") as f:
    f.read(16)
    dis.dis(f.read())
```

```
py d.py > dump.txt
```

Alternative tool: <https://github.com/zrax/pycdc>


Now our teammate asked Claude AI to get some initial python code for us:

```python
import os
import sys
import random

data = (os.urandom(8), 1)
if data[0] == b'OwO_QuQ_':
    print('Oops! something went wrong, run again')
else:
    rand_data, one = data
    print("You're Lucky")
    print('Here is your flag: ', end='')

arr1 = []
arr2 = []
arr3 = []
arr4 = []

arr2.append(96)
arr2.append(98)
arr4.append(198)
arr4.append(31)
arr2.append(68)
arr2.append(160)
arr3.append(180)
arr3.append(165)
arr3.append(115)
arr3.append(203)
arr2.append(172)
arr3.append(177)
arr4.append(60)
arr2.append(115)
arr3.append(17)
arr3.append(166)
arr2.append(20)
arr2.append(108)
arr3.append(196)
arr2.append(25)
arr3.append(255)
arr4.append(167)
arr4.append(17)
arr4.append(1)
arr4.append(132)
arr2.append(122)
arr3.append(127)
arr4.append(106)
arr4.append(195)
arr2.append(208)
arr4.append(19)
arr3.append(70)
arr4.append(38)
arr4.append(151)
arr3.append(172)
arr3.append(55)
arr2.append(71)
arr3.append(11)
arr2.append(158)
arr2.append(63)
arr3.append(204)
arr3.append(20)
arr4.append(203)
arr4.append(163)
arr4.append(211)
arr4.append(27)
arr4.append(73)
arr2.append(233)
arr4.append(98)
arr2.append(59)

summed = arr2 + arr3 + arr4

for i1 in range(0, 50):
    three = 3
    try:
        try:
            for j1 in range(25, 50):
                random.seed(j1 / (j1 - j1))
            one = three ** i1
        except ZeroDivisionError:
            one = one ** three
    except:
        print("IN EXCEPTION")
        pass

    one = three ** i1
    a, b, c = (1, 2, 3)
    MOD = 1000000007

    for j1 in range(one):
        match (j1 % 3, j1 % 5):
            case (0, 0):
                a, b, c = b, c, a % MOD
            case (0, _):
                a, b, c = b, c, (a + b + c) % MOD
            case (1, _):
                a, b, c = b, c, (a + b) % MOD
            case (2, _):
                a, b, c = b, c, (a + c) % MOD

    char = summed[i1] ^ (a & 255)
    print(chr(char), end='')
    sys.stdout.flush()
```

If you run it you see it start printing the flag but needs to be sped up. 

First, split the main loop into 2 loops, plus some other tidying up:

```python
summed = [96, 98, 68, 160, 172, 115, 20, 108, 25, 122, 208, 71, 158, 63, 233, 59, 180, 165, 115, 203, 177, 17, 166, 196, 255, 127, 70, 172, 55, 11, 204, 20, 198, 31, 60, 167, 17, 1, 132, 106, 195, 19, 38, 151, 203, 163, 211, 27, 73, 98]
MOD = 1000000007

flag = ""
for i in range(0, 50):
    if (i >= 25):
        limit = limit**3
    else:
        limit = 3**i


    a, b, c = (1, 2, 3)
    for _ in range(limit // 15):
        a, b, c = (
            (1 * a + 54 * b + 87 * c) % MOD,
            (34 * b + 55 * c) % MOD,
            (55 * b + 89 * c) % MOD,
        )

    for j in range(limit % 15):
        if j % 3 == 0 and j % 5 == 0:
            a, b, c = b, c, a % MOD
        elif j % 3 == 0:
            a, b, c = b, c, (a + b + c) % MOD
        elif j % 3 == 1:
            a, b, c = b, c, (a + b) % MOD
        else:
            a, b, c = b, c, (a + c) % MOD

    flag += chr(summed[i] ^ (a & 255))
    print(flag)
```

This recurrence relation can then be changed to matrix exponentiation!

```python
    a, b, c = (1, 2, 3)
    for _ in range(limit // 15):
        a, b, c = (
            (1 * a + 54 * b + 87 * c) % MOD,
            (0 * a + 34 * b + 55 * c) % MOD,
            (0 * a + 55 * b + 89 * c) % MOD,
        )
```

Immediately you can see a big improvement:

```python
from sage.all import *

summed = [96, 98, 68, 160, 172, 115, 20, 108, 25, 122, 208, 71, 158, 63, 233, 59, 180, 165, 115, 203, 177, 17, 166, 196, 255, 127, 70, 172, 55, 11, 204, 20, 198, 31, 60, 167, 17, 1, 132, 106, 195, 19, 38, 151, 203, 163, 211, 27, 73, 98]
MOD = 1000000007
M = matrix(GF(MOD), [
    [1, 54, 87], 
    [0, 34, 55], 
    [0, 55, 89]
])

flag = ""
for i in range(0, 50):
    if (i >= 25):
        limit = limit**3
    else:
        limit = 3**i

    iters = limit//15
    a, b, c =  M**iters * vector([1, 2, 3])

    for j in range(limit % 15):
        if j % 3 == 0 and j % 5 == 0:
            a, b, c = b, c, a % MOD
        elif j % 3 == 0:
            a, b, c = b, c, (a + b + c) % MOD
        elif j % 3 == 1:
            a, b, c = b, c, (a + b) % MOD
        else:
            a, b, c = b, c, (a + c) % MOD

    flag += chr(summed[i] ^ (int(a) & 255))
    print(flag)
```

Now is where we went down a rabbithole...

We worked with matrix diagonalisation which was an improvement but not enough to get the entire flag:

```python
from sage.all import *

summed = [96, 98, 68, 160, 172, 115, 20, 108, 25, 122, 208, 71, 158, 63, 233, 59, 180, 165, 115, 203, 177, 17, 166, 196, 255, 127, 70, 172, 55, 11, 204, 20, 198, 31, 60, 167, 17, 1, 132, 106, 195, 19, 38, 151, 203, 163, 211, 27, 73, 98]
MOD = 1000000007
M = matrix(GF(MOD), [
    [1, 54, 87], 
    [0, 34, 55], 
    [0, 55, 89]
])


D, P = M.change_ring(ZZ).diagonalization(GF(MOD**2)) # fails in GF(MOD)
assert M == P * D * P**-1
print(D)

# POC
assert M**5 == P * D**5  * P**-1

def power_diagonal_matrix(D, x):
    L = list(D)
    K = GF(MOD**2)
    a, b, c = K(L[0][0]), K(L[1][1]), K(L[2][2])
    print(a, b, c)
    aa, bb, cc = a**x, b**x, c**x
    ans = diagonal_matrix(K, [aa, bb, cc])
    return ans

assert D**5 == power_diagonal_matrix(D, 5)

flag = ""
for i in range(0, 50):
    if (i >= 25):
        limit = limit**3
    else:
        limit = 3**i

    iters = limit//15
    #a, b, c =  M**iters * vector([1, 2, 3])
    matrix_pow = P * power_diagonal_matrix(D, iters)  * P**-1
    a, b, c = matrix_pow.change_ring(GF(MOD)) * vector([1, 2, 3])


    for j in range(limit % 15):
        if j % 3 == 0 and j % 5 == 0:
            a, b, c = b, c, a % MOD
        elif j % 3 == 0:
            a, b, c = b, c, (a + b + c) % MOD
        elif j % 3 == 1:
            a, b, c = b, c, (a + b) % MOD
        else:
            a, b, c = b, c, (a + c) % MOD

    flag += chr(summed[i] ^ (int(a) & 255))
    print(flag)
```

Anyways scrapping that and going back to the previous one, the 'aha' moment was realising we can change 

```python
    a, b, c =  M**iters * vector([1, 2, 3])
```

to 

```python
    a, b, c =  M**(iters % 1000000008) * vector([1, 2, 3])
```

(the multiplicative order):

```
sage: MOD = 1000000007
....: M = matrix(GF(MOD), [
....:     [1, 54, 87],
....:     [0, 34, 55],
....:     [0, 55, 89]
....: ])
....: print(M.multiplicative_order())
1000000008
```


and it still works. Now the problem remaining is calculating iters mod 1000000008

The integer division `iters = limit//15` poses a small challenge, when we do modular division we'll  have to brute a bit below to get the correct value.

```
>>> pow(15, -1, 1000000008)
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
ValueError: base is not invertible for the given modulus

>>> from math import gcd
>>> gcd(15, 1000000008)
3
```

Another problem, we can't divide by 3.

```python
for i in range(0, 50):
    if (i >= 25):
        limit = limit**3
        assert limit == (3**24) ** (3**(i-24))
    else:
        limit = 3**i
```

Luckily limit is a power of 3, so when calculating it we can just reduce the exponent by 1. 

Now to brute the division error:

```python
MOD2 = 1000000008
for i in range(0, 26):
    if (i >= 25):
        limit = limit**3
        assert limit == (3**24) ** (3**(i-24))
        print((limit//15) % MOD2)

        t = pow(3, (24*(3**(i-24)) - 1), MOD2)
        for k in range(-5, 0):
            iters = ((t+k) * pow(5, -1, MOD2)) % MOD2
            print(k, iters)
    else:
        limit = 3**i
```

```
128107877
-5 328107878
-4 928107883
-3 528107880
-2 128107877
-1 728107882
```

so we should use k=-2

A quick test:

```python
MOD2 = 1000000008
for i in range(0, 35):
    if (i >= 25):
        limit = limit**3
        assert limit == (3**24) ** (3**(i-24))
        print((limit//15) % MOD2)

        t = pow(3, (24*(3**(i-24)) - 1), MOD2)
        print(((t-2) * pow(5, -1, MOD2)) % MOD2)
    else:
        limit = 3**i
```

Looks good:

```
128107877
128107877
887672165
887672165
258270413
258270413
358089125
358089125
...
```

Final script putting it together:

```python
from sage.all import *

summed = [96, 98, 68, 160, 172, 115, 20, 108, 25, 122, 208, 71, 158, 63, 233, 59, 180, 165, 115, 203, 177, 17, 166, 196, 255, 127, 70, 172, 55, 11, 204, 20, 198, 31, 60, 167, 17, 1, 132, 106, 195, 19, 38, 151, 203, 163, 211, 27, 73, 98]
MOD = 1000000007
M = matrix(GF(MOD), [
    [1, 54, 87], 
    [0, 34, 55], 
    [0, 55, 89]
])

flag = ""
for i in range(0, 50):
    if i >= 25:
        MOD2 = 1000000008
        t = pow(3, (24*(3**(i-24)) - 1), MOD2)
        iters = ((t-2) * pow(5, -1, MOD2)) % MOD2
        limit = pow(3, (24*(3**(i-24))), 15)
    else:
        limit = 3**i
        iters = limit//15
        limit = limit % 15

    a, b, c =  M**(iters % 1000000008) * vector([1, 2, 3])
    for j in range(limit):
        if j % 3 == 0 and j % 5 == 0:
            a, b, c = b, c, a % MOD
        elif j % 3 == 0:
            a, b, c = b, c, (a + b + c) % MOD
        elif j % 3 == 1:
            a, b, c = b, c, (a + b) % MOD
        else:
            a, b, c = b, c, (a + c) % MOD

    flag += chr(summed[i] ^ (int(a) & 255))
    print(flag)

# bctf{we1rd_pyth0nc0d3_so1v3_w1th_f4s7_M47r1x_Mu1t}
```


<br>

# Fetus-RSA

<https://writeup.gldanoob.dev/bitsctf/>

```python
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes

e = 31337
n = 515034877787990680304726859216098826737559607654653680536655175803818486402820694536785452537613547240092505793262824199243610743308333164103851365420630137187276313271869670701737383708742526677
a = iroot(n //  (27*63), 5)[0]
for i in range(-10000, 10000):
    if n % (a+i) == 0:
        p1 = a + i
        break

p2 = p1 
p3 = next_prime(p2 * 3)
p4 = next_prime(p3 * 3)
p5 = next_prime(p4 * 7)
assert p1*p2*p3*p4*p5 == n

M = matrix(Zmod(n), [
    [247714609729115034577268860647809503348452679955541765864525644036519903244610407544592438833012659821363982836831477850927621505723503202914955484784761468695340160789629882004055804409080695867, 331625142917011732363496584111977497826539848810596405639715608289185491230192921594585113936516744954068559616963395888825085234835086592835782522823153199824647815923311303312529222423487842184 ,55437288185949549641415195099137917985198178875175317590356850868652628068256771878957686344008331498612071069691453711091201145528626750365270496738628725699281809961803599963127434726167609435 ,514660916099185196031776141538776359410382339048282799109733569738126784171011249457518653961429789338579350043906060924939800730829826389077489637524528092592193187169747629063004980325000389554 ,432908737089369750416720813650504950741227543859957288298129130571557758647818791153409184252564534925607409378801765727301405467691263041798341098982058861749568674152447781841703730861074171486 ],
    [104171307746966345345857299403770324392522334886728513788970028646835780770090370816961277474173463662053179135418083415763603092683905102293259569143230591686555033557056635683615214642425173517, 281995809329109899498417283591516891672267505291547187769414960759245222376040526984420670509684233818236456944690830422135256653807646369718495017051487254128669606210585168140190305476396414836 ,448210297704655248563230644309382726474650012116320871206976601497778210586480264554625801730855872456388662647389829317946932942681549854741993522145903386318540208729036379511878276729211658861 ,399193502999265141959383452857091791757532600793923480036782294759164203783245516880539439411508616363396395258745387111132143827593272610961260623660064934154238955120293971424750525097551648180 ,448909699677346701183758951038319440723583288307818355958233994863175886710495171317606803723159576428485212274726596045235998230677229224379125716760136092533604817049730746550292371970711497032 ],
    [10383824979618791372207750490225860866360446289011667617367731854443817405025701872398853456038612719059056477356275566409859556622099910727870579661815727983662245805512246175424036918556245316, 3042212133475156282375315438954933898496627384941849067508473136817427432524109900983912625376319043681252528210663860374506706029777992048856493297280439498831646567645849063286941560111486091 ,303901520908845557762276355500926092138935908381564097855093945643653520650021074626397106363589843089839561176214123648988682404983806374183953260408815900582907133898417354283905163971086566554 ,385414980407334346707284477209921028250475161696209076212214696858828374481374774762344617183479700018626970039426895699261230837253656355202103718574806419224338390036737550645417315148014935208 ,172437598435610362668691083369422058178612127588567286669952095014310724933793758671802664372505747578789080527221296229242137567445447449560987571505575740311394634799579166058011734727404038041 ],
    [459726837943530454128170171077760511486009487765694189770202436458018005866133157577824055980174845256397040485330898693944501922148000904627621334536523927325451030816598478315788682056071758797 ,318766645374831072244114015670117551595181174553017703335802708316885112551395705202907958737214488185739954176085085611052360624160681549561415131064529778955941226762589967588568203157586014646 ,485361005374731090711430490780588207888099824436671620066599360058262282812311497518237782819588602409946446254729349547214950452718084694554650900064587640931729162822096611158015732013679765115 ,442488981185685119421099225895492967006907103880489001122993678677306129218035946328038537612725434883858276836497639772750576738969390151812664236525222680918250542360570252193283310559820113337 ,294017672174100375503817924437430140826863578191649796300540064690169411498877218939778928997294952104395700469268399214549954967540991489929488976904050382049934179672641195866868009511101289284 ],
    [394288980150370144394508377797340867635320394706221783789360450886862330500083595146934277232717671435601428999455723360437715407992902972393377872146437245909234935183690525050686313034961250106 , 174537062539250527750306397111216900339583030576848484858177223085331307339246744122607759453386390209872407563526999813562242756044330978624067706177762337375480164381575660119163723806663394768 ,167378817268639407255382001659131271694745168867873206910416580974376327982114272760583238198872032832961214636912981493082249850676384736073683786291369414678559758485110038329085571864758144806 ,479478683656492256273719495784577239188841595512723735000697935028851355713461770920044121053505358284609828319371252306609569657211738503902322975549066701614139339082341370785743668742796520457 , 468925056254460005965810812432459057693038841264871939568448625553319440670497244388153862616274082271409346691280049609288322448351851208172939513793874861880752049454593563028452119997997329883 ]
])

nn = 5
g = prod([prod([(p**nn -  p**i) for i in range(nn)]) for p in [p1, p2, p3, p4, p5]])
d = pow(e, -1, g)

for row in M**d:
    for i in row:
        print(long_to_bytes(int(i)).decode(), end='')

# bctf{c0ngr4ts_y0u_35c4p3d_th3_m4tr1c3s, but really how? what color is your honda civic? sorry i just need to make this long.}
```


<br>

# shamir-for-dummies

Our goal is to get sum_of_shares = n*s

Then we send some_factor=n so it gets divided by n and we're left with s

```
sum_of_shares = 
  s + c2*x1 + c3*x1^2 + c4*x1^3 + ...
+ s + c2*x2 + c3*x2^2 + c4*x2^3 + ...
+ s + c2*x3 + c3*x3^2 + c4*x3^3 + ...
...
(mod p)



 = n*s + 
+ c2 * (x1+x2+x3+x4+...)
+ c3 * (x1^2+x2^2+x3^2+x4^2+...)
+ c4 * (x1^3+x2^3+x3^3+x4^3+...)
...
(mod p)
```

The trick is to send the roots of unity!

```python
from Crypto.Util.number import long_to_bytes
from pwn import remote

io = remote('gold.b01le.rs', int(5006))
io.recvuntil(b'use')
io.recvline()
io.recvuntil(b'n =')
n = int(io.recvline().decode().strip())
io.recvuntil(b'p =')
p = int(io.recvline().decode().strip())

g = GF(p)
roots = g(1).nth_root(n, all=True)
r = g(1).nth_root(n)
roots = [r ** i for i in range(n)]

for r in roots:
	io.sendlineafter(b'> ', str(r).encode())
io.sendlineafter(b'> ', str(n).encode())
io.recvuntil(b"The shares P(X_i)'s were':\n")
shares = eval(io.recvline())
print(shares)
s = (sum(shares) * pow(n, -1, p)) % p
print(long_to_bytes(s))
# bctf{P0LYN0m14l_1N_M0d_P_12_73H_P0W3Rh0u23_0F_73H_5h4M1r}
```
