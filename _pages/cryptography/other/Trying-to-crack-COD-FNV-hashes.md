---
permalink: /cryptography/other/Trying-to-crack-COD-FNV-hashes
title: Trying to crack COD FNV hashes
---

<br>


I was sent the following code from HalfInchPunisher, working with some others reverse engineering Call of Duty.

```c
#define ull unsigned long long

ull fnv64(const char* string) {
    ull hash = 0xCBF29CE484222325;
    ull prime = 0x100000001B3;

    for (int i = 0; string[i]; ++i) {
        char cur = string[i];
        if ((unsigned char)(cur - 'A') <= 25)
            cur |= 0x20;

        if (cur == '\\')
            cur = '/';

        hash ^= cur;
        hash *= prime;
    }

    return hash;
}
```

Along with a few example hashes:

```
0xC5BE054CB26B3829
0x233B0E2B30E00445
0x92A366D1A86FD4D5
0x50B2F8C43DA48808
```

<br>

Translating to sage code:

```python
def fnv64(string):
    string=string.lower().replace("\\","/")
    hsh = 0xCBF29CE484222325
    prime = 0x100000001B3
    for c in string.encode():
        hsh = (hsh^^c)*prime
    return hsh % 2**64
```

Each xor operation with one of the input characters can be described as +/- some value from -128 to 128. 

Then it's a linear system mod 2**64 to solve, with n unknowns for an input string of length n.


```python
def lattice_enumeration(L, bound, sol_cnt):
    from fpylll import IntegerMatrix, LLL
    from fpylll.fplll.gso import MatGSO
    from fpylll.fplll.enumeration import Enumeration
    A = IntegerMatrix.from_matrix(L)
    LLL.reduction(A)
    M = MatGSO(A)
    M.update_gso()
    size = int(L.nrows())
    enum = Enumeration(M, sol_cnt)
    answers = enum.enumerate(0, size, (size * bound**2), 0, pruning=None)
    for _, s in answers:
        v = IntegerMatrix.from_iterable(1, A.nrows, map(int, s))
        sv = v * A
        if abs(sv[0, -1]) <= bound:
            yield sv[0]

def linear_solver(xx, target, M, avg, bound, sol_cnt=10_000):
    from tqdm import tqdm
    P = PolynomialRing(ZZ, "ap", len(xx))
    aps = P.gens()
    aa = [ap + avg for ap in aps]
    f = sum([a * x for a, x in zip(aa, xx)]) - target
    L = matrix(f.coefficients()).T
    L = block_matrix([[M, 0], [L, 1]])
    L[:, 0] *= 2**100
    if sol_cnt > 100_000:
        rows = tqdm(lattice_enumeration(L.change_ring(ZZ), bound, sol_cnt))
    else:
        rows = lattice_enumeration(L.change_ring(ZZ), bound, sol_cnt)
    for row in rows:
        neg = row[-1]
        if neg not in (-1, 1):
            continue
        sol = [neg * row[i+1] for i in range(len(xx))]
        if f(*sol) % M != 0:
            continue
        sol = [x + avg for x in sol]
        yield sol

def fnv64(string):
    string=string.lower().replace("\\","/")
    hsh = 0xCBF29CE484222325
    prime = 0x100000001B3
    for c in string.encode():
        hsh = (hsh^^c)*prime
    return hsh % 2**64

def rev(sol):
    hsh = 0xCBF29CE484222325
    p = 0x100000001B3
    ret = ""
    a = hsh
    b = hsh
    for s in sol:
        a += s
        for x in range(128):
            if a == b^^x:
                ret += chr(x)
                b ^^= x
                break
        a *= p
        b *= p
    return ret.encode()

def solve(target, n, sol_cnt=10_000):
    hsh = 0xCBF29CE484222325
    p = 0x100000001B3
    rets = []
    for sol in linear_solver([p**(n - i) for i in range(n)], target - hsh*p**n, 2**64, avg=0, bound=128, sol_cnt=sol_cnt):
        ret = rev(sol)
        if len(ret) == n:
            print()
            print(ret)
            rets.append(ret)
    return rets


# one of the actual examples
solve(0xC5BE054CB26B3829, 8)

solve(fnv64("abcdefg"), 7)
solve(fnv64("abcdefgh"), 8)
solve(fnv64("abcdefghi"), 9, sol_cnt=20_000)
#print(solve(fnv64("abcdefghij"), 10, sol_cnt=1_000_000))    # didn't find anything
```

This code works well for up to 9 chars, but at 10 there seems to be too many possibilities...

I decided to experiment with the FindInstance function from Wolfram anyways.


<br>

# Using Wolfram Language

I had some troubles installing on arch, but seems easier on debian-based distros. 

You need to install the [Wolfram Engine](https://www.wolfram.com/engine/) and [WolframScript](https://www.wolfram.com/wolframscript/)

```
sudo dpkg -i WolframScript_14.0.0_LINUX64_amd64.deb
sudo ./WolframEngine_14.0.0_LINUX.sh
wolframscript
pip install wolframclient
```

Some other documentation:

<https://reference.wolfram.com/language/ref/program/wolframscript.html>

<https://support.wolfram.com/45743>

<https://reference.wolfram.com/language/ref/FindInstance.html>

<https://reference.wolfram.com/language/WolframClientForPython/>

<https://blog.wolfram.com/2019/05/16/announcing-the-wolfram-client-library-for-python/>



```python
from wolframclient.evaluation import WolframLanguageSession
from wolframclient.language import wlexpr
session = WolframLanguageSession()

def find_instances(xx, LB, UB, target, M, sol_cnt=1000):
    n = len(xx)
    expr = 'FindInstance[{'
    expr += '+'.join(f'{xx[i]}*x{i}' for i in range(n)) + f'+ k*{{{M}}} == {target}'
    expr += ','  + ','.join(f'x{i}<{UB},x{i}>{LB}' for i in range(n))
    expr += '},{' + ','.join(f'x{i}' for i in range(n)) + f',k}},Integers, {sol_cnt}]'
    for sol in session.evaluate(wlexpr(expr)):
        yield [x[1] for x in sol[:-1]]

def fnv64(string):
    string=string.lower().replace("\\","/")
    hsh = 0xCBF29CE484222325
    prime = 0x100000001B3
    for c in string.encode():
        hsh = (hsh^c)*prime
    return hsh % 2**64

def rev(sol):
    hsh = 0xCBF29CE484222325
    p = 0x100000001B3
    ret = ""
    a = hsh
    b = hsh
    for s in sol:
        a += s
        for x in range(128):
            if a == b^x:
                ret += chr(x)
                b ^= x
                break
        a *= p
        b *= p
    return ret.encode()

def solve(target, n, sol_cnt=1):
    hsh = 0xCBF29CE484222325
    p = 0x100000001B3
    rets = []
    for sol in find_instances([p**(n - i) for i in range(n)], -128, 128, target - hsh*p**n, 2**64, sol_cnt=sol_cnt):
        ret = rev(sol)
        if len(ret) == n:
            rets.append(ret)
    return rets

# one of the actual examples
print(solve(0xC5BE054CB26B3829, 8))

print(solve(fnv64("abcdefg"), 7))
print(solve(fnv64("abcdefgh"), 8))
print(solve(fnv64("abcdefghi"), 9, sol_cnt=500))
print(solve(fnv64("abcdefghij"), 10, sol_cnt=50_000))
#print(solve(fnv64("abcdefghijk"), 11, sol_cnt=2))    # doesn't seem to work

session.terminate()
```
