---
permalink: /cryptography/other/CRYPTO-CTF-2024
title: CRYPTO CTF 2024
---

<br>
<br>

[Challenge Files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2024/CRYPTO%20CTF)

<br>

# Alibos

```python
	c = (pkey + d ** 2 * m) % (10 ** d)
```

Rearranging for m:

```python
from Crypto.Util.number import *

pkey = 8582435512564229286688465405009040056856016872134514945016805951785759509953023638490767572236748566493023965794194297026085882082781147026501124183913218900918532638964014591302221504335115379744625749001902791287122243760312557423006862735120339132655680911213722073949690947638446354528576541717311700749946777
enc  = 6314597738211377086770535291073179315279171595861180001679392971498929017818237394074266448467963648845725270238638741470530326527225591470945568628357663345362977083408459035746665948779559824189070193446347235731566688204757001867451307179564783577100125355658166518394135392082890798973020986161756145194380336

d = len(str(pkey))
m = ((enc-pkey) * pow(d**2, -1, 10**d)) % 10**d
print(m)
print(long_to_bytes(int(str(m)[:108])))

# 6170704326493336128242608193100736601774626903966803036318189045381903593682775829229200905376968543264526051111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
# CCTF{h0M3_m4De_cRyp70_5ySTeM_1N_CryptoCTF!!!}
```


# Beheaded

This was like the famous ECB penguin, you could rescale it in gimp or use a block where all pixels are the same colour without needing to find the key. 

# Mashy

Guessy trash, had to guess that sh was `a483b30944cbf762d4a3afc154aad825`. 

Then you can just send a bunch of md5 collisions, so that xor(h1, h2) is b'\x00\x00 ...'








# Forghan

```
...::::: CCTF{f!nD1N9_7wIn_5m0OtH_1nT3GErS!!!} :::::...
```

# RM2

```python
from pwn import *
from Crypto.Util.number import *
from gensafeprime import generate

io = remote('01.cr.yp.toc.tf', 13371)
io.read()

def get_super_safe_prime():
    while True:
        x = generate(1024)
        if isPrime(2*x+1):
            return x

#p = get_super_safe_prime()
#q = get_super_safe_prime()
p = 176190361114405660140775371642244103546320715334539918001492645857771593552107955448402648350633693638480545186750598651678784235721661177218038230550079910726963779269165803404500415338229375745350440434088252741915552117559295023850055262211395546349293984582637753204891730267351496766430177371001101202579
q = 174673912453530565721373096945468158471423845542688334400192438665743138238497195281153045123700977896509756132766346293652660746134615199680910832008097698850013139496501456054035329932355735673848807210672424697329408424184179185667926436594508177456167574196681896497806043904509301791431726034346952707019

io.sendline(f'{p},{q}'.encode())
c1 = int(io.readline().decode().split('= ')[1])
c2 = int(io.readline().decode().split('= ')[1])

# 	c1, c2 = pow(m1, e, (p - 1) * (q - 1)), pow(m2, e, (2*p + 1) * (2*q + 1))
e = 65537
m1=pow(c1, pow(e, -1, ((p-1)//2-1) * ((q-1)//2-1)), (p-1)*(q-1))
m2=pow(c2, pow(e, -1, 4*p*q), (2*p+1)*(2*q+1))

secret_string = long_to_bytes(m1) + long_to_bytes(m2)
io.read()
io.sendline(secret_string)
print(io.read().decode())

# CCTF{i_l0v3_5UpeR_S4fE_Pr1m3s!!}
```

# Alilbols

# Nabat

# Nazdone

# Joe-19

```python
import requests
from Crypto.Util.number import *
from tqdm import *

resp = requests.get('https://zacharyratliff.org/files/eMillionDigits.txt')
e_digits = resp.content.decode().split('\n')[4][2:]
n = 8098851734937207931222242323719278262039311278408396153102939840336549151541408692581651429325092535316359074019383926520363453725271849258924996783681725111665666420297112252565291898169877088446887149672943461236879128453847442584868198963005276340812322871768679441501282681171263391133217373094824601748838255306528243603493400515452224778867670063040337191204276832576625227337670689681430055765023322478267339944312535862682499007423158988134472889946113994555274385595499503495488202251032898470224056637967019786473820952632846823442509236976892995505554046850101313269847925347047514591030406052185186963433
c = 7109666883988892105091816608945789114105575520302872143453259352879355990908149124303310269223886289484842913063773914475282456079383409262649058768777227206800315566373109284537693635270488429501591721126853086090237488579840160957328710017268493911400151764046320861154478494943928510792105098343926542515526432005970840321142196894715037239909959538873866099850417570975505565638622448664580282210383639403173773002795595142150433695880167315674091756597784809792396452578104130341085213443116999368555639128246707794076354522200892568943534878523445909591352323861659891882091917178199085781803940677425823784662

for i in trange(len(e_digits)-154):
    for k in [154,155]:
        p = int(e_digits[i:i+k])
        if isPrime(p) and p.bit_length() == 512 and n%p == 0:
            d = pow(65537, -1, p-1)
            print(long_to_bytes(pow(c, d, p)))

# CCTF{ASIS_h1r3_7aL3nT5_t0_cO1La8orAt3_!N_Crypto_CTF!}
```

# Honey

# Ahoo

(No source provided.)

```
$ nc 00.cr.yp.toc.tf 17371
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Welcome to Ahoo task! Given integer n, find the smallest positive   ┃
┃ integer c such that n * c has the minimum number of 1 bits in its   ┃
┃ binary representation. Completing all steps will reveal the flag :) ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
┃ Please send the number of 1 bits in n * c and the integer c for
┃ n = 3823, separated by comma: 
```

Had to pass several rounds of this.

Check:

<https://arxiv.org/pdf/2002.02731>

<https://github.com/FinnLidbetter/sturdy-numbers>

# Vantuk

# Ally

Credit @ctfguy

<https://www.imo-official.org/problems/IMO2012SL.pdf>

Check N4^

```python
from pwn import remote
from Crypto.Util.number import getPrime

def get_special_prime(nbit):
    while True:
        p = getPrime(nbit)
        if p%4 == 1:
            return p

io = remote('01.cr.yp.toc.tf', '13777')
for _ in range(20):
    io.recvuntil(b'your ')
    nbit = int(io.recvuntil(b'-').decode()[:-1])
    p = get_special_prime(nbit)
    io.sendline(str(p).encode())
    k = (p-1)//4
    x, y = 2*k+1, k
    io.sendline(f"{x},{y}".encode())
io.interactive()

# CCTF{Di0phaNtinE_eQuaT1on_iZ_4n_equ4tion_wiTh_int3ger_solu7Ions_0nly!}
```

# Soufia

(No source provided.)

Credit @ctfguy

```python
from pwn import *

conn = remote('03.cr.yp.toc.tf', 13377)

def read_val(conn):
    for _ in range(4):
        print(conn.recvline().decode())

    s=conn.recvline().decode()
    print(s)
    y1 = int(s.split('=')[1].split(',')[0].strip())
    s=conn.recvline().decode()
    print(s)
    x2 = int(s.split('(')[1].split(')')[0])
    y2 = int(s.split('=')[1].split('┃')[0].strip())
    conn.recvline().decode()
    return int(0),int(x2),int(y1),int(y2)

def cal(val):
    a = (y2 - y1) // (x2 - x1)
    b = y1 - a * x1
    return (a * val) + b

x1,x2,y1,y2 = read_val(conn)
print(x1,x2,y1,y2)

s=conn.recvline().decode()
val = int(s.split('(')[1].split(')')[0])
ans=cal(val)
conn.sendline(str(ans).encode())
print(conn.recvline().decode())
def conti():
        s=conn.recvline().decode()
        print(s)
        val = int(s.split('(')[1].split(')')[0])
        ans=cal(val)
        conn.sendline(str(ans).encode())
        print(conn.recvline())

while True:
    conti()
```

```
[+] Opening connection to 03.cr.yp.toc.tf on port 13377: Done
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓

┃ .::   Soufia is a random oracle, your mission is to break it   ::. ┃

┃ We know that f: Z → Z and for all integers `x' and `y' we have:    ┃

┃     f(t * x) + t * f(y) = f(f(x + y)) for constant integer `t'.    ┃

┃ Also, f(0) = 209907020941535864741588746126965728575,              ┃

┃ and   f(91) = 1369168415328908069957513174528303837593             ┃

0 91 209907020941535864741588746126965728575 1369168415328908069957513174528303837593
┃ Good job, try the next step 2

┃ Please send the f(45):

b'\xe2\x94\x83 Good job, try the next step 3\n'
┃ Please send the f(32):

b'\xe2\x94\x83 Good job, try the next step 4\n'
┃ Please send the f(155):

b'\xe2\x94\x83 Good job, try the next step 5\n'
┃ Please send the f(356):

...

b'\xe2\x94\x83 Good job, try the next step 18\n'
┃ Please send the f(3910397):

b'\xe2\x94\x83 Good job, try the next step 19\n'
┃ Please send the f(2008442):

b'\xe2\x94\x83 Good job, try the next step 20\n'
┃ Please send the f(14329881):

b"\xe2\x94\x83 Congratz! You got the flag: b'CCTF{A_funCti0nal_3qu4tiOn_iZ_4_7yPe_oF_EquAtioN_tHaT_inv0lVe5_an_unKnOwn_funCt!on_r4tH3r_thAn_juS7_vArIabl3s!!}'\n"
```

# Melek

# Solmaz

```python
px, py = (1338, 9218578132576071095213927906233283616907115389852794510465118810355739314264)
qx, qy = (3454561753909947353764378180794889923919743476068813953002808647958908878895, 17267599534808803050751150297274989016063324917454246976792837120400888025519)
A = qx*(py^2-px^3) - px*(qy^2-qx^3)
p = 30126567747372029007183424263223733382328264316268541293679065617875255137317
assert A%p == 0

c = (py^2 - px^3) * pow(px, -1, p) % p
E = EllipticCurve(GF(p), [c, 0])
P = E(px, py)
Q = E(qx, qy)
m = Q.log(P)
print(bytes.fromhex(f'{m:02x}'))
# 3cC_d1ViSibil!7Y
```


# Rehawk

<https://gitlab.inria.fr/capsule/code-for-module-lip/-/blob/main/attack/attack_Hawk_totally_real.sage>

