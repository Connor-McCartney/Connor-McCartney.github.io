---
permalink: /cryptography/other/corCTF-2022
title: corCTF 2022
---

<br>

[Challenge Files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2022/corCTF)

<br>

# tadpole

<br>

We're given f(31337) and f(f(31337))

$$ f(31337) \equiv (a \cdot 31337 + b) \ (mod\ p) $$

$$ f(f(31337)) \equiv (a \cdot f(31337) + b) \ (mod\ p) $$

let y = f(31337)

let z = f(f(31337))

$$y + k_1 \cdot p \equiv a \cdot 31337 + b$$

$$z + k_2 \cdot p \equiv a \cdot y + b$$

Then p = gcd(k1 * p, k2 * p) = gcd(a * 31337 + b - y, a * y + b - z)

```python
from Crypto.Util.number import long_to_bytes
from math import gcd

a = 7904681699700731398014734140051852539595806699214201704996640156917030632322659247608208994194840235514587046537148300460058962186080655943804500265088604049870276334033409850015651340974377752209566343260236095126079946537115705967909011471361527517536608234561184232228641232031445095605905800675590040729
b = 16276123569406561065481657801212560821090379741833362117064628294630146690975007397274564762071994252430611109538448562330994891595998956302505598671868738461167036849263008183930906881997588494441620076078667417828837239330797541019054284027314592321358909551790371565447129285494856611848340083448507929914
y = 52926479498929750044944450970022719277159248911867759992013481774911823190312079157541825423250020665153531167070545276398175787563829542933394906173782217836783565154742242903537987641141610732290449825336292689379131350316072955262065808081711030055841841406454441280215520187695501682433223390854051207100
z = 65547980822717919074991147621216627925232640728803041128894527143789172030203362875900831296779973655308791371486165705460914922484808659375299900737148358509883361622225046840011907835671004704947767016613458301891561318029714351016012481309583866288472491239769813776978841785764693181622804797533665463949

p = gcd(a*31337+b-y, a*y+b-z)
print(long_to_bytes(p))
#corctf{1n_m4th3m4t1c5,_th3_3ucl1d14n_4lg0r1thm_1s_4n_3ff1c13nt_m3th0d_f0r_c0mput1ng_th3_GCD_0f_tw0_1nt3g3rs} <- this is flag adm
```

<br>

# luckyguess

We must solve x:

$$x \equiv a \cdot x + b \ (mod\ p)$$

$$-b \equiv a \cdot x -x \ (mod\ p)$$

$$-b \equiv x(a-1) \ (mod\ p)$$

$$-b \cdot (a-1)^{-1}\equiv x \ (mod\ p)$$

Then send both the starting point and guess as x.

```python
from pwn import *
io = remote('be.ax', 31800)
p = 2**521 - 1

io.recvuntil(b"a = ")
a = int(io.recvline().strip())
io.recvuntil(b"b =")
b = int(io.recvline().strip())

x = (-b * pow(a-1, -1, p)) % p

io.recvuntil(b"point:")
io.sendline(str(x).encode())
io.recvuntil(b"guess?")
io.sendline(str(x).encode())
print(io.readline())

#wow, you are truly psychic! here, have a flag: corctf{r34l_psych1c5_d0nt_n33d_f1x3d_p01nt5_t0_tr1ck_th15_lcg!}
```

<br>

# Exchange

```python
a_priv = randbelow(p)
b_priv = randbelow(p)

def f(s):
    return (a * s + b) % p

def mult(s, n):
    for _ in range(n):
        s = f(s)
    return s

A = mult(s, a_priv)
B = mult(s, b_priv)
```

I started by creating an equation from the mult function.

I used some examples (ignoring mod p) to see a pattern:

$$f(f(s)) = a^2s + ab + b$$

$$f(f(f(s))) = a^3s + a^2b + ab + b$$

$$f(f(f(f(s)))) = a^4s + a^3b + a^2b + ab + b$$

$$f(f(f(f(f(s))))) = a^5s + a^4b + a^3b + a^2b + ab + b$$

Then notice the last terms form a geometric sequence:

$$\sum_{i=1}^n{b \cdot a^{i-1}} = \frac{b(1-a^n)}{1-a}$$

So the mult function is:

$$mult(s, n) = a^ns + b(1-a^n)(1-a)^{-1} \ (mod\ p)$$

```python
def mult_alternative(s, n):
    return (pow(a,n,p)*s + b*(1-pow(a,n,p))*pow(1-a, -1, p)) % p
```

<br>

Next solve priv_a (n):

$$A = a^n \cdot s \ + b (1-a^n) \cdot (1-a)^{-1} \ (mod \ p)$$

let u = pow(1-a, -1, p)

$$A = a^n \cdot s \ + b (1-a^n) \cdot u \ (mod \ p)$$

$$A = a^n \cdot s \ + b \cdot u - b \cdot a^n \cdot u \ (mod \ p)$$

$$A - b \cdot u = a^n (s - b\cdot u) \ (mod \ p)$$

$$(A - b \cdot u)(s - b\cdot u)^{-1} = a^n \ (mod \ p)$$

Now it is a discrete log problem, and luckily p-1 is smooth so Pohlig Hellman solves it fast. 

<br>

```python
from Crypto.Util.number import *  
from Crypto.Cipher import AES  
from Crypto.Util.Padding import pad  
from hashlib import sha256  
from sympy.ntheory.residue_ntheory import _discrete_log_pohlig_hellman  
  
p = 142031099029600410074857132245225995042133907174773113428619183542435280521982827908693709967174895346639746117298434598064909317599742674575275028013832939859778024440938714958561951083471842387497181706195805000375824824688304388119038321175358608957437054475286727321806430701729130544065757189542110211847  
a = 118090659823726532118457015460393501353551257181901234830868805299366725758012165845638977878322282762929021570278435511082796994178870962500440332899721398426189888618654464380851733007647761349698218193871563040337609238025971961729401986114391957513108804134147523112841191971447906617102015540889276702905  
b = 57950149871006152434673020146375196555892205626959676251724410016184935825712508121123309360222777559827093965468965268147720027647842492655071706063669328135127202250040935414836416360350924218462798003878266563205893267635176851677889275076622582116735064397099811275094311855310291134721254402338711815917  
s = 35701581351111604654913348867007078339402691770410368133625030427202791057766853103510974089592411344065769957370802617378495161837442670157827768677411871042401500071366317439681461271483880858007469502453361706001973441902698612564888892738986839322028935932565866492285930239231621460094395437739108335763  
A = 27055699502555282613679205402426727304359886337822675232856463708560598772666004663660052528328692282077165590259495090388216629240053397041429587052611133163886938471164829537589711598253115270161090086180001501227164925199272064309777701514693535680247097233110602308486009083412543129797852747444605837628  
B = 132178320037112737009726468367471898242195923568158234871773607005424001152694338993978703689030147215843125095282272730052868843423659165019475476788785426513627877574198334376818205173785102362137159225281640301442638067549414775820844039938433118586793458501467811405967773962568614238426424346683176754273  
output = "e0364f9f55fc27fc46f3ab1dc9db48fa482eae28750eaba12f4f76091b099b01fdb64212f66caa6f366934c3b9929bad37997b3f9d071ce3c74d3e36acb26d6efc9caa2508ed023828583a236400d64e"  
  
def mult_alternative(s, n):  
   return (pow(a,n,p)*s + b*(1-pow(a,n,p))*pow(1-a, -1, p)) % p  
  
u = pow(1-a, -1, p)  
a_priv = (_discrete_log_pohlig_hellman(p, ((A - b*u) * pow(s - u*b, -1, p)) % p, a))  
b_priv = (_discrete_log_pohlig_hellman(p, ((B - b*u) * pow(s - u*b, -1, p)) % p, a))  
  
assert mult_alternative(A, b_priv) == mult_alternative(B, a_priv)  
shared = mult_alternative(A, b_priv)  
key = sha256(long_to_bytes(shared)).digest()[:16]  
iv = bytes.fromhex(output[:32])  
enc = bytes.fromhex(output[32:])  
cipher = AES.new(key, AES.MODE_CBC, iv=iv)  
print(cipher.decrypt(pad(enc, 16)))  
  
#corctf{th1s_lcg_3xch4ng3_1s_4_l1ttl3_1ns3cur3_f0r_n0w}
```

<br>

# hidE

Basically common modulus attack, with some bruting the seed and possible e.

```python
from pwn import *  
from Crypto.Util.number import *  
import time  
from tqdm import tqdm  
from math import gcd  
  
def encrypt_flag():  
   io.recvuntil(b'Choose an option: ')  
   io.sendline(b'1')  
   io.recvuntil(b'Here is your encrypted flag: ')  
   return int(io.recvline().strip(), 16)  
  
def common_modulus_attack(c1, c2, e1, e2, n):  
   s1 = pow(e1, -1, e2)  
   s2 = int((gcd(e1,e2) - e1 * s1) // e2)  
   temp = pow(c2, -1, n)  
   m1 = pow(c1,s1,n)  
   m2 = pow(temp,-s2,n)  
   return (m1 * m2) % n  
  
io = remote('be.ax', 31124)  
io.recvuntil(b'modulus is: ')  
n = int(io.recvline().strip())  
c1 = encrypt_flag()  
c2 = encrypt_flag()  
  
tt = int(time.time())  
for t in range(tt-2, tt+2):  
   random.seed(t)  
   e = [random.randint(1, n) for i in range(20)]  
   for i in tqdm(e):  
       for j in e[::-1]:  
           if gcd(i,j) == 1:  
               m = common_modulus_attack(c1, c2, i, j, n)  
               if b'corctf{' in long_to_bytes(m):  
                   print(long_to_bytes(m))  
                   break  
  
#corctf{y34h_th4t_w4snt_v3ry_h1dd3n_tbh_l0l}
```
