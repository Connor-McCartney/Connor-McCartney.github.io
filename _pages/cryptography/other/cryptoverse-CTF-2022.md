---
permalink: /cryptography/other/cryptoverse-CTF-2022
title: cryptoverse CTF 2022
---

<br>

[Challenge Files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2022/cryptoversectf)

<br>

# Warmup 1

Decode the following ciphertext: cGlwZ3N7cG5yZm5lXzY0X3Nnan0=.

This is just base64 and then rot13 <br>
<https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)ROT13(true,true,false,13)&input=Y0dsd1ozTjdjRzV5Wm01bFh6WTBYM05uYW4w>

cvctf{caesar_64_ftw}

<br>

# Warmup 2

First described by Giovan Battista Bellaso in 1553, this cipher is easy to understand and implement, but it resisted all attempts to break it until 1863, three centuries later.

Remember: The Key to success is determination.

fzvxw{hqtegmfr_lw_msf_scrslg_kvwlhyk_fpr_kxg?}

<br>

<https://www.dcode.fr/vigenere-cipher>

cvctf{vigenere_is_too_guessy_without_the_key?}

<br>

# Warmup 3

You should recognize this instantly.

-.-. ...- -.-. - ..-. -- ----- .-. ..... ...-- .. ... -. ----- - ..... ----- ..-. ..- -.

Note: Add { and } around the flag. Flag is all lower case.

<br>

<https://www.dcode.fr/morse-code>

CVCTFM0R53ISN0T50FUN

cvctf{m0r53isn0t50fun}

<br>

# Warmup 4

Last warmup. You should get it fast if you use any social media.

Ｉn sｃｉencｅ fіctіοｎ, ｍetａνerse ｉs ｉtｅrａtiｏｎоf the Iｎternｅｔ as a sⅰｎgｌe, universal and immersive virtual world that is facilitated by the use of virtual reality and augmented reality headsets.

Note: Wrap the message you decoded in cvctf{}.

Note 2: This challenge involves some steganography tool related to a social media.

<br>

https://holloway.nz/steg/

cvctf{secretsaretobeh1dd3n}

<br>

# Substitution

Substitution is a cryptographic technique where a plaintext is replaced by a ciphertext. The ciphertext is a substitution of the plaintext.

Here is a very simple CTF-related substitution cipher. Find out the flag.

Hxpkdiz kcz Osxe ja x apzhjxs ljvr go jvogimxkjgv azhdijkf hgmpzkjkjgva. Kcziz xiz kcizz hgmmgv kfpza, Uzgpxirf, Xkkxhl Rzozvhz xvr mjyzr.
Jo fgd cxwz ojedizr gdk kcz xqgwz mzaaxez, cziz ja fgdi osxe, pszxaz xrr hdisf qixhlzka qzogiz adqmjaajgv: hwhkoxwzifajmpszadqakjkdkjgv

<br>

<http://quipqiup.com/>

cvctf{averysimplesubstitution}

<br>

# RSA 1

The n is so large that it's not possible to factor it. Or is it?

```py
n = 0x7c05a45d02649367ebf6f472663119777ce5f9b3f2283c7b03471e9feb1714a3ce9fa31460eebd9cd5aca7620ecdb52693a736e2fcc83d7909130c6038813fd16ef50c5ca6f491b4a8571289e6ef710536c4615604f8e7aeea606d4b5f59d7adbec935df23dc2bbc2adebbee07c05beb7fa68065805d8c8f0e86b5c3f654e651
e = 0x10001
ct = 0x35b63f7513dbb828800a6bcd708d87a6c9f33af634b8006d7a94b7e3ba62e6b9a1732a58dc35a8df9f7554e1168bfe3de1cb64792332fc8e5c9d5db1e49e86deb650ee0313aae53b227c75e40779a150ddb521f3c80f139e26b2a8880f0869f755965346cd28b7ddb132cf8d8dcc31c6b1befc83e21d8c452bcce8b9207ab76e
```

<br>

In this challenge the author simply uploaded the factors of n to <http://factordb.com>

```py
n = 0x7c05a45d02649367ebf6f472663119777ce5f9b3f2283c7b03471e9feb1714a3ce9fa31460eebd9cd5aca7620ecdb52693a736e2fcc83d7909130c6038813fd16ef50c5ca6f491b4a8571289e6ef710536c4615604f8e7aeea606d4b5f59d7adbec935df23dc2bbc2adebbee07c05beb7fa68065805d8c8f0e86b5c3f654e651
e = 0x10001
ct = 0x35b63f7513dbb828800a6bcd708d87a6c9f33af634b8006d7a94b7e3ba62e6b9a1732a58dc35a8df9f7554e1168bfe3de1cb64792332fc8e5c9d5db1e49e86deb650ee0313aae53b227c75e40779a150ddb521f3c80f139e26b2a8880f0869f755965346cd28b7ddb132cf8d8dcc31c6b1befc83e21d8c452bcce8b9207ab76e
p = 8156072525389912369788197863285751656042515380911795404436333529629416084362735262281722179416240983448945672233749861517470671156357917601583268804973543
q = n//p
d = pow(e, -1, (p-1)*(q-1))
flag = long_to_bytes(pow(ct, d, n))
print(flag)
#b'cvctf{f4c70rDB_15_p0w3rfu1}'
```

<br>

# RSA 2

Part 1: p is given so I just solve mod p.

Part 2: p and q are close so use Fermat factorisation.

```python
from Crypto.Util.number import long_to_bytes
from gmpy2 import isqrt, is_square


def part_1():
    p = 12288921312928905252066685441095433471598896337203035200127730574490649634697724898647492622180506530440487680891254318894425463123822054731206592479004443
    e = 65537
    ct = 477810761866191067447439010305549740987167655432530443522675033657369723786048842040442154581768138072922232065577919832660311749722811153131700616623491664129964460155641257628035443854025940214881843381516731886468952698960658032624539602708992596947417406064936755170646371843885836414699432839708624613424771775975205847206849618916244266841618040141811129621887797853986955912887940909492892452582572860341612662314834825669781647797309123819689482025845274220304090264258705352508079779481185568502456351966535816576336785374480232497981502094209095089630736220344636425703292835013643094434503207582627896342361399742142907352683789098893088197300169085876182759566238368607976127565393402067969228801828020040880864943530678429628691860709498984558508259930639978577326355937177663775355912658421617068727167293437739623405125007006701483686062823345676708079582959894137740287934681427537716868544192722130809973616745739204044297782671776628943651456537315348365219970412662895839161961678735840519665352845752401565067760259782075123983614541164569034238760232355335830834765695866518376808132147639516485086981529017855541096845234038238351348084096654297016020126411818954399154297310283491861804817107618193838806953155
    assert gcd(e, p-1) == 1
    m = mod(ct, p).nth_root(e)
    return long_to_bytes(int(m))


def fermat(n):
    assert n % 2 != 0
    a = isqrt(n)
    b = a**2 - n
    while not is_square(b):
        a += 1
        b = a**2 - n
    p = int(a + isqrt(b))
    return p, n//p


def part_2():
    n = 85205911394226026500275210536070696774019932212697333763455696542783046512381571530938238053084695855960959283864240454975283339087819608102879636911292604501949036560581582119299425314297903747045402522844383142899951990239300430074264857012937328120615676527671685158004985642485347181510738733455006987563
    e = 65537
    ct = 36094975186594521686754290222264536503273789013798395884104790217898195008843408149451748239377299652426931967019223980259457768048183972055991854928660562680316115848049030120068763050175827932483663365464482727317050056562889546636425655657765772098105202889353529152305437946280810771045676951442322243838
    p, q = fermat(n)
    d = pow(e, -1, (p-1)*(q-1))
    m = pow(ct, d, n)
    return long_to_bytes(int(m))


def main():
    p1 = part_1()
    p2 = part_2()
    print(p1 + p2)


if __name__ == "__main__":
    main()
    
#b'cvctf{Hensel_Takagi_Lifting,but_Fermat_is_better?}'
```

<br>

# RSA 3

CRT attack but there is 1/10 chance we get a bad value, so collect more than you need <br>
then zip the lists and use random.sample

```python
from pwn import remote, process
from sympy.ntheory.modular import crt
from gmpy2 import iroot
from random import sample
from Crypto.Util.number import long_to_bytes

def get_values():
    n_list = []
    c_list = []
    while len(n_list) < 30:
        #io = process("./server.py")
        io = remote("137.184.215.151", 22629)
        n = int(io.readline().split()[-1])
        e = int(io.readline().split()[-1])
        c = int(io.readline().split()[-1])
        io.close()
        if e == 17:
            n_list.append(n)
            c_list.append(c)
            print(len(n_list))
    return n_list, c_list

def main():
    n_list, c_list = get_values()
    for _ in range(1000):
        x = list(zip(n_list, c_list))
        ns = []
        cs = []
        for a, b in sample(x, 17):
            ns.append(a)
            cs.append(b)
        flag = iroot(crt(ns, cs)[0], 17)[0]
        flag = long_to_bytes(flag)
        if b"ctf" in flag:
            print(flag)

def crt_test():
    m = 999999999999999999999999999999999999999
    e = 3
    from Crypto.Util.number import getPrime
    ns = [getPrime(100)*getPrime(100) for _ in range(e)]
    cs = [pow(m, e, n) for n in ns]
    print(m == iroot(crt(ns, cs)[0], e)[0])

if __name__ == "__main__":
    main()

#b'cvctf{Hastad_with_e=65537_might_be_slow}'
```

<br>

# CyberMania

I got this piece of ciphertext from my friend who is a Cyber Mania. It must have hidden something...

```
NDAgNmIgNzEgNmEgNjkgM2EgMzIgM2QgNDIgM2YgM2QgNzUgMjcgNjIgNmEgM2QgNWQgNjUgMmQgNWMgM2MgNjMgMjggM2IgNzMgM2MgNDEgNDkgNWQgMzUgM2IgNDQgNTcgMzggNzAgM2IgMmYgNDMgMjYgNDIgM2EgMzAgMjggMmMgMmEgNDAgM2IgNTMgNGEgNTYgM2MgMjkgNmQgNTUgMzYgM2EgMmMgMmMgMzQgMmQgNDAgMzkgM2YgMjEgNDAgM2MgNWYgMmMgNzQgNjEgNDEgMzQgNGIgNWIgMjQgM2UgMjMgNjYgNGUgM2IgNDAgNmIgNzAgMjIgNzUgM2QgNWYgNjcgNjAgNTcgM2QgNjEgNDYgNTUgNGIgNDEgMzggNTEgMjEgNmUgM2IgNjUgNmYgNTEgMjkgM2QgMjUgNDcgNzIgMjggNDAgMzcgMzMgNTMgMjMgM2QgMjUgM2YgNzEgMjEgM2EgMmUgNGIgMzQgNTggNDEgMzggMzQgNTMgNDkgM2QgNWQgNDAgNmEgNjkgM2MgMjggNGIgNmUgNjYgM2EgMmUgNDkgMzAgM2QgMzkgNjkgNTkgNWYgM2YgM2MgNjAgNGYgMmEgNjAgM2MgMmEgMjkgNWIgNjMgNDEgMzggNGYgNjUgMzUgMzkgNjkgNTAgMmUgNWUgM2IgNjYgMmIgNGYgM2MgM2EgNDkgNjYgMzUgM2EgMzkgNmQgNTQgNjUgNmUgM2QgNWQgNTQgNGEgNzEgM2MgMjkgNjQgMjQgNjYgM2QgMjkgNGMgNTcgNGUgNDAgNmYgNzUgMzMgNDggM2QgNTkgNGYgNDEgNjcgNDAgM2MgNzQgNGYgNWMgM2EgMmUgMzcgNjAgMzAgM2IgNjYgMjMgNDcgNjYgM2QgMjUgMjQgNTAgNDUgM2QgNzQgNjkgNTEgNDQgM2MgMjggMzkgNjIgM2YgM2UgMjYgMzggMmUgMzUgM2MgNDMgNDMgMjIgNDcgM2IgNGEgNWQgMzYgNGMgM2UgMjIgM2EgNDcgNGMgM2IgNDggM2YgMzcgNjggM2IgMmYgNGEgNmMgNWEgM2IgNjUgNjYgNGIgNTkgM2EgNDkgNjQgNmMgNmEgM2QgMjcgMjUgNDMgNzUgM2IgNDYgNDYgMmQgMjMgM2MgNDUgNDMgNmUgNmIgM2MgNDUgMzQgMzUgNzMgM2QgMjYgNjEgMjEgM2QgM2IgNDggMzUgNTMgNjcgNDAgMzkgNDAgMjYgNWMgMzkgNjYgMjQgNjAgNWIgM2QgNWQgNTIgNzQgM2IgNDAgNmYgNmMgMzkgNDMgNDEgNGYgNGIgMjEgNTMgM2MgMmEgMzIgNjEgNWUgNDAgMzcgM2MgNjUgMjUgNDAgNTQgNDggNGUgMzEgM2EgMzIgNDYgNjAgNGIgM2UgMjMgNjUgMzAgNmUgM2MgMjggMjcgNGEgNzUgM2MgNWYgMmMgNTEgMjIgNDAgNzIgMjIgNTggNmUgM2IgMmQgMjUgNGMgMjYgMzkgNjkgNTAgNzEgMjggNDAgM2IgMzkgM2QgNTYgM2MgMjkgNjQgNWIgNGUgNDEgNGYgNGIgMzkgNjAgM2QgNWYgNzAgNTAgNWQgNDEgNTMgNmEgMmIgNTcgM2QgNzQgNzMgMzMgMjQgM2UgMjYgNGEgMmIgMzMgM2MgNjAgNjkgMmIgMzIgNDAgMzcgNGUgNjQgNDYgM2IgNDQgNDMgNTggM2QgM2IgMmYgNDMgMjMgNmYgM2IgNWYgNTYgMmEgNjMgM2MgNWUgNzAgMjggNDYgNDAgNmYgNWEgNDUgMmYgNDAgNTAgNWYgNzMgNTggNDAgNTQgNWEgNjIgNjUgM2QgMjkgMjkgNTAgNmMgNDEgMzggM2QgNjUgMjggNDEgMzYgM2MgNGQgMzMgNDAgMzcgNGYgNzMgNTQgNDEgNGYgNmYgNTEgNTAgNDEgMzkgNTUgMzEgMjI
```

<br>

Base64 -> hex -> base85 -> base64 -> base58 -> <https://cryptoji.com>

cvctf{3m0j1_c4n_L34K_7h1ng5}

<br>

# Big Rabin

