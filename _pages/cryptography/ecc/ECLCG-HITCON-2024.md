---
permalink: /cryptography/ecc/ECLCG-HITCON-2024
title: ECLCG - HITCON 2024
---

<br>

Challenge:

<https://github.com/maple3142/My-CTF-Challenges/tree/master/HITCON%20CTF%202024/ECLCG>

```python
from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from fastecdsa.curve import secp256k1
from hashlib import sha256
from secrets import randbelow


G = secp256k1.G
q = secp256k1.q


def sign(d, z, k):
    r = (k * G).x
    s = (z + r * d) * pow(k, -1, q) % q
    return r, s


def verify(P, z, r, s):
    u1 = z * pow(s, -1, q) % q
    u2 = r * pow(s, -1, q) % q
    x = (u1 * G + u2 * P).x
    return x == r


def lcg(a, b, p, x):
    while True:
        x = (a * x + b) % p
        yield x


msgs = [
    b"https://www.youtube.com/watch?v=kv4UD4ICd_0",
    b"https://www.youtube.com/watch?v=IijOKxLclxE",
    b"https://www.youtube.com/watch?v=GH6akWYAtGc",
    b"https://www.youtube.com/watch?v=Y3JhUFAa9bk",
    b"https://www.youtube.com/watch?v=FGID8CJ1fUY",
    b"https://www.youtube.com/watch?v=_BfmEjHVYwM",
    b"https://www.youtube.com/watch?v=zH7wBliAhT0",
    b"https://www.youtube.com/watch?v=NROQyBPX9Uo",
    b"https://www.youtube.com/watch?v=ylH6VpJAoME",
    b"https://www.youtube.com/watch?v=hI34Bhf5SaY",
    b"https://www.youtube.com/watch?v=bef23j792eE",
    b"https://www.youtube.com/watch?v=ybvXNOWX-dI",
    b"https://www.youtube.com/watch?v=dt3p2HtLzDA",
    b"https://www.youtube.com/watch?v=1Z4O8bKoLlU",
    b"https://www.youtube.com/watch?v=S53XDR4eGy4",
    b"https://www.youtube.com/watch?v=ZK64DWBQNXw",
    b"https://www.youtube.com/watch?v=tLL8cqRmaNE",
]

if __name__ == "__main__":
    d = randbelow(q)
    P = d * G

    p = getPrime(0x137)
    a, b, x = [randbelow(p) for _ in range(3)]
    rng = lcg(a, b, p, x)

    sigs = []
    for m, k in zip(msgs, rng):
        z = int.from_bytes(sha256(m).digest(), "big") % q
        r, s = sign(d, z, k)
        assert verify(P, z, r, s)
        sigs.append((r, s))
    print(f"{sigs = }")

    with open("flag.txt", "rb") as f:
        flag = f.read().strip()
    key = sha256(str(d).encode()).digest()
    cipher = AES.new(key, AES.MODE_CTR)
    ct = cipher.encrypt(flag)
    nonce = cipher.nonce
    print(f"{ct = }")
    print(f"{nonce = }")
```

```
sigs = [(49045447930003829750162655581084595201459949397872275714162821319721992870137, 21098529732134205108109967746034152237233232924371095998223311603901491079093), (8434794394718599667511164042594333290182358521589978655877119244796681096882, 72354802978589927520869194867196234684884793779590432238701483883808233102754), (98981626295463797155630472937996363226644024571226330936699150156804724625467, 78572251404021563757924042999423436619062431666136174495628629970067579789086), (39876682309182176406603789159148725070536832954790314851840125453779157261498, 57493814845754892728170466976981074324110106533966341471105757201624065653133), (65207470758289014032792044615136252007114423909119261801100552919825658080689, 35801670032389332886673836105411894683051812268221960643533854039645456103322), (62310615350331421137050446859674467271639363124966403418757056624834651785981, 35521772482874533704942922179876531774398711539124898773478624535131725819343), (112968103298671409136981160931495676458802276287280410415332578623201858813402, 69136482735760979952358359721969881674752452777485098096528689791122554903910), (65185852906255515620576935005939230631603582432998989514260597054881976462676, 85379997570993122627264764907519703985819259494167121515303052416417601678111), (89525951822575634807524099747751997083879407738240060351122435098952102365970, 73032937908295382442051096857786822685807890991333822263666894552392531234105), (10051482171127490286979879686762557184173302546674808492445781875620932719446, 26217862064468074441046914792412948081058029471697661868711999974556608497458), (8842758449685028748615236698968197767772820788773190926335075554397256573640, 31652804170027719136589492610452674938583230853203431940531961290992398961987), (23751070894286517351443200111133743672788640335816140651282619979550868046371, 62545547750389706281745923819072901405095067763677430386609805435019439100532), (73526459114147520989492697207756783950511563270716718674108128391637651652182, 70851054921933366241324896134628440370210434216441807412696261358563604784468), (57753594385723283080008450150285839290328959323728215111064869128180653466512, 48682503345807264543892350428384011994195616727229911040222271121395096668630), (65263395028919805249304292530249376748389080058707453448295007353333046365479, 10365290276028966530454805043630476285018698618883354555344947391544138993674), (87437293666767613034832827186884716590065056433713359026118257811657437100576, 89500859891014369107213802143650102492250691913844472777312272074978411403745), (82006715584380621917183646856144618837928013528296150149335800289034986391573, 66403597255556240236430083902481022812584785679596388450322939858389337923701)]
ct = b'\xc6*\x17\xcce\xc1y\xb8\xb4\x8d\x87L\xf8\x81QK\xf4\x02\xf2\xf7\x8d\xe0\xe8\x92\xc7\xe7\x8fg\xb1M\xb4.\x89\x18\xf5\x7f\xed\xc3I\x92\x82\xfd\xfe9\x95\xc9(\x90\xce\x93\xb9+\xce\x958\xf3\x05PH'
nonce = b'6\xe7m\xcc\x8e\x0eG '
```

<br>

# Solve

Our LCG equations are mod p and our signature equations are mod q, 

working with both mod p and mod q appears to be a difficult component of this challenge. 

Additionally, we aren't even given p!

<br>

Signature equations (for known s,r,z,q):

$$
d \equiv \frac{s \cdot k - z}{r}  \ \text{ (mod q)}
$$

<br>

If you elimintate d (actually this is not useful to solve this chall):

$$
k_n \equiv \frac{r_n s_c}{r_c s_n} \cdot k_c + \frac{r_c z_n - r_n z_c}{r_c s_n} \ \text{ (mod q)}
$$

Thank you to [genni](https://genni21.github.io/) for sharing his solution!

<br>

If you rearrange for k_next - k_current (is useful):

$$
k_n - k_c \equiv \frac{d \cdot r_n + z_n}{s_n} - \frac{d \cdot r_c+z_c}{s_c}    \ \text{ (mod q)}
$$

$$
k_n - k_c \equiv \frac{d \cdot r_n}{s_n} + \frac{z_n}{s_n} - \frac{d \cdot r_c}{s_c} - \frac{z_c}{s_c}    \ \text{ (mod q)}
$$

$$
k_n - k_c \equiv \left( \frac{r_n}{s_n} - \frac{r_c}{s_c} \right) \cdot d + \frac{z_n}{s_n} - \frac{z_c}{s_c}    \ \text{ (mod q)}
$$

I'll just rewrite as some new variables for convenience, every:

$$
kk_i \equiv u_i \cdot d + v_i    \ \text{ (mod q)}
$$

$$
kk_i \equiv u_i \cdot d + v_i + y_i \cdot q
$$


Now make a lattice basis like Stern's algorithm, annihilating each kk_i. 

<https://sci-hub.se/10.1007/11506157_5>


Then you can take the LLL outputs and directly solve the same system of equations, recovering every kk_i. 

(The LCG relation is handled implicitly)


```python
from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from fastecdsa.curve import secp256k1
from hashlib import sha256
from secrets import randbelow

def sign(d, z, k):
    r = (k * G).x
    s = (z + r * d) * pow(k, -1, q) % q
    return r, s

def lcg(a, b, p, x):
    while True:
        x = (a * x + b) % p
        yield x

G = secp256k1.G
q = secp256k1.q
Fq = GF(q)
msgs = [b"https://www.youtube.com/watch?v=kv4UD4ICd_0",    b"https://www.youtube.com/watch?v=IijOKxLclxE",    b"https://www.youtube.com/watch?v=GH6akWYAtGc",    b"https://www.youtube.com/watch?v=Y3JhUFAa9bk",    b"https://www.youtube.com/watch?v=FGID8CJ1fUY",    b"https://www.youtube.com/watch?v=_BfmEjHVYwM",    b"https://www.youtube.com/watch?v=zH7wBliAhT0",    b"https://www.youtube.com/watch?v=NROQyBPX9Uo",    b"https://www.youtube.com/watch?v=ylH6VpJAoME",    b"https://www.youtube.com/watch?v=hI34Bhf5SaY",    b"https://www.youtube.com/watch?v=bef23j792eE",    b"https://www.youtube.com/watch?v=ybvXNOWX-dI",    b"https://www.youtube.com/watch?v=dt3p2HtLzDA",    b"https://www.youtube.com/watch?v=1Z4O8bKoLlU",    b"https://www.youtube.com/watch?v=S53XDR4eGy4",    b"https://www.youtube.com/watch?v=ZK64DWBQNXw",    b"https://www.youtube.com/watch?v=tLL8cqRmaNE"]
d = randbelow(q)
print(f'{d = }\n')
P = d * G
p = getPrime(0x137)
a, b, x = [randbelow(p) for _ in range(3)]
rng = lcg(a, b, p, x)

sigs = []
for m, k in zip(msgs, rng):
    z = int.from_bytes(sha256(m).digest(), "big") % q
    r, s = sign(d, z, k)
    sigs.append((r, s, z, k))

us = []
vs = []
kks = []
for (r_c, s_c, z_c, k_c), (r_n, s_n, z_n, k_n) in zip(sigs[:-1], sigs[1:]):
    u = int(Fq(r_n)/Fq(s_n) - Fq(r_c)/Fq(s_c))
    v = int(Fq(z_n)/Fq(s_n) - Fq(z_c)/Fq(s_c))
    kk = int(Fq(k_n - k_c))
    assert kk == (u*d + v) % q
    us.append(u)
    vs.append(v)
    kks.append(kk)
    
M = (Matrix(us[:-2]).T
     .augment(vector(vs[:-2]))
     .augment(vector(us[1:-1]))
     .augment(vector(vs[1:-1]))
)
M = block_matrix([
    [M, 1],
    [q, 0]
])
M[:, :4] *= 2**1000
M = M.LLL()

PR = PolynomialRing(ZZ, [f"kk_{i}" for i in range(15)])
sym_delta_nonces = PR.gens()
eqs_nonces = []

for row in M[:11]: # somewhat arbitrary
    comb = [int(x) for x in row[4:]]
    assert 0 == (vector(comb) * vector(Fq, us[:-2])) % q
    assert 0 == (vector(comb) * vector(Fq, vs[:-2])) % q
    assert 0 == (vector(comb) * vector(Fq, us[1:-1])) % q
    assert 0 == (vector(comb) * vector(Fq, vs[1:-1])) % q
    for i in range(2):
        eqs_nonces.append(
            sum([a*b for a, b in zip(comb, sym_delta_nonces[i:i+14])])
        )

A, _ = Sequence(eqs_nonces).coefficients_monomials()
ker = A.right_kernel().basis_matrix() 

for mm in [-1, 1]:
    recovered_nonces = mm * ker[0]
    recovered_d = Fq(recovered_nonces[0] - vs[0]) / us[0]
    print(kks[:-1] == [int(i%q) for i in recovered_nonces])
    print(mm, recovered_d == d, recovered_d)
    print()
```
