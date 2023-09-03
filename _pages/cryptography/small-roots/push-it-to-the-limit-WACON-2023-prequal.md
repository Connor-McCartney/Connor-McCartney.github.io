---
permalink: /cryptography/small-roots/push-it-to-the-limit-WACON-2023-prequal
title: Push It To The Limit - WACON 2023 Prequal
---

<br>

# Challenge Files

```python
from Crypto.Util.number import bytes_to_long, getStrongPrime

with open("flag.txt", "rb") as f:
    m = bytes_to_long(f.read())

SIZE = 1024
p = getStrongPrime(SIZE)
q = getStrongPrime(SIZE)
n = p * q
e = 0x10001
c = pow(m, e, n)

p_msb = p - p % (2 ** (SIZE // 2))

print(f"{n = }")
print(f"{c = }")
print(f"{p_msb = }")
```

```
n = 24712135189687942739677490021030751776088469214818275631687482073531676912880823269667196936095460153002434759403063429337125873794523587731746689517070810687221399532024093572951282737818446579992570629531618780373767724789390101166147862982539311016801595612323156816999866783427829783286164172896802725820761659256555627406518829192800217880692359914672894220547306033679060066475600137205045054015651689487444267401130160872050085589597109014374199731072611044277806027332254214020499883131062627540945260814416104971893858787291926267157394988131329441246648393933117451348643609850156730059817506513924523851733
c = 19285290054358264594160191119053363484661054622854927550086540936229836207751905061897299540539735528766803248513199392889410922209106513019275525361297785136742517684745274089253401778969310170805452788203125136583847273167894915706201708268160138117578035286292385848441833691098676192230945185815890266453215404593242520989429750775723053435372661531195966551199012453469748764989624596296116016310586535749198878013241527430239006604194528859329192316989103910514620735894760979900228995139208829267762309798970482895132300580481270883276800390489213520429816698576642899381455153039281329012831320123165127378159
p_msb = 161405912451824860188834725646055524173328544131300133372580621368926433914138476338787007253318242142454894032713487340762003643551953941809023233323836630063065828499586237941251339865726273353740523275987884928619323490566227483094269770052935277592758770273832919929071652425379016974435907024060290170880
```

<br>

# Solve

Didn't play this ctf btw, just a post-solve. <br>
It's very similar to this one. <br>
<https://connor-mccartney.github.io/cryptography/small-roots/corrupt-key-1-picoMini> <br>
Half of the upper bits of p are given, the only difference is now p is 1024 bits not 512 bits. <br>
This makes it a lot slower, so I edited my previous code to include 3 optimisations from maple3142. 

<br>

# Optimisation 1

Just a minor optimisiation: since p must be odd, we can reduce the bound by 1 bit by changing

```python
        f = p_high * 2**(p_bits-p_high_bits) + x
        x = small_roots(f, X=2**(p_bits-p_high_bits), beta=0.5, m=m)
```

to 

```python
        f = p_high * 2**(p_bits-p_high_bits) + 2*x + 1
        x = small_roots(f, X=2**(p_bits-p_high_bits-1), beta=0.5, m=m)
```

<br>

# Optimisation 2

Using flatter for faster LLL. 

```
sudo pacman -S eigen --noconfirm
cd ~/Documents
git clone https://github.com/keeganryan/flatter
cd flatter
cmake .
make -j4
sudo ln -s ~/Documents/flatter/bin/flatter /usr/local/bin/flatter
```

```python
from subprocess import check_output
from re import findall

def flatter(M):
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))
```

And now we can do `B =  flatter(B)` instead of `B = B.LLL()`

<br>

# Experiment

Here's the full value of p:

```python
p = 161405912451824860188834725646055524173328544131300133372580621368926433914138476338787007253318242142454894032713487340762003643551953941809023233323836632396674586164821404065443903169766781702197174899338334027128103867874700640036605974611327518250687560220955598412727224450293311080620976484498655311739
```

Now let's analyse how long bruting a different number of bits takes:

```python
from Crypto.Util.number import *
import time
from subprocess import check_output
from re import findall

def flatter(M):
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))

def small_roots(f, X, beta=1.0, m=None):
    N = f.parent().characteristic()
    delta = f.degree()
    if m is None:
        epsilon = RR(beta^2/f.degree() - log(2*X, N))
        m = max(beta**2/(delta * epsilon), 7*beta/delta).ceil()
    t = int((delta*m*(1/beta - 1)).floor())
    
    f = f.monic().change_ring(ZZ)
    P,(x,) = f.parent().objgens()
    g  = [x**j * N**(m-i) * f**i for i in range(m) for j in range(delta)]
    g.extend([x**i * f**m for i in range(t)]) 
    B = Matrix(ZZ, len(g), delta*m + max(delta,t))

    for i in range(B.nrows()):
        for j in range(g[i].degree()+1):
            B[i,j] = g[i][j]*X**j

    B =  flatter(B)
    f = sum([ZZ(B[0,i]//X**i)*x**i for i in range(B.ncols())])
    roots = set([f.base_ring()(r) for r,m in f.roots() if abs(r) <= X])
    return [root for root in roots if N.gcd(ZZ(f(root))) >= N**beta]

def recover(p_high, n, m):
        p_bits = (len(bin(n))-2)//2
        p_high_bits = len(bin(p_high)) - 2
        PR.<x> = PolynomialRing(Zmod(n))
        f = p_high * 2**(p_bits-p_high_bits) + 2*x + 1
        x = small_roots(f, X=2**(p_bits-p_high_bits-1), beta=0.5, m=m)
        if x == []:
                return None
        p = int(f(x[0]))
        return p

n = 24712135189687942739677490021030751776088469214818275631687482073531676912880823269667196936095460153002434759403063429337125873794523587731746689517070810687221399532024093572951282737818446579992570629531618780373767724789390101166147862982539311016801595612323156816999866783427829783286164172896802725820761659256555627406518829192800217880692359914672894220547306033679060066475600137205045054015651689487444267401130160872050085589597109014374199731072611044277806027332254214020499883131062627540945260814416104971893858787291926267157394988131329441246648393933117451348643609850156730059817506513924523851733
p = 161405912451824860188834725646055524173328544131300133372580621368926433914138476338787007253318242142454894032713487340762003643551953941809023233323836632396674586164821404065443903169766781702197174899338334027128103867874700640036605974611327518250687560220955598412727224450293311080620976484498655311739

m = 1
for bits in range(15, 5, -1):
    p_high = p >> (512 - bits)
    while True:
        starttime = time.time()
        p = recover(p_high, n, m=m)
        t = time.time() - starttime
        if is_prime(p):
            print(f"bruting {bits} bits with m={m} will take {int(2**bits * t // 3600)} hours (single-threaded)")
            break
        m += 1
```

```
bruting 15 bits with m=17 will take 63.0 hours (single-threaded)
bruting 14 bits with m=18 will take 38.0 hours (single-threaded)
bruting 13 bits with m=19 will take 23.0 hours (single-threaded)
bruting 12 bits with m=21 will take 17.0 hours (single-threaded)
bruting 11 bits with m=23 will take 12.0 hours (single-threaded)
bruting 10 bits with m=25 will take 9.0 hours (single-threaded)
bruting 9 bits with m=27 will take 6.0 hours (single-threaded)
bruting 8 bits with m=30 will take 4.0 hours (single-threaded)
bruting 7 bits with m=33 will take 3.0 hours (single-threaded)
bruting 6 bits with m=38 will take 2.86 hours (single-threaded)
bruting 5 bits with m=44 will take 2.54 hours (single-threaded)
bruting 4 bits with m=53 will take 2.53 hours (single-threaded)
```
