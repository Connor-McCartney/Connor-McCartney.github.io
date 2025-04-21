---
permalink: /cryptography/rsa/xorsa-UMassCTF-2025
title: xorsa - UMassCTF 2025
---

<br>

Challenge:

```python
from Crypto.Util import number

flag = b"REDACTED"
bits = 1024

p = number.getPrime(bits)
q = number.getPrime(bits)

n = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = number.inverse(e, phi)
extra = 75

c = pow(int.from_bytes(flag, 'big'), e, n)
print(f"n: {hex(n)}")
print(f"e: {hex(e)}")
print(f"c: {hex(c)}")
print(f"partial p^q: {hex((p^q) >> (bits // 2 - extra))}")
```

<br>

```
n: 0x46dbd0780b618c8dea0dc6b13a47a5b40bca30b96ed5b15e1be1ffad2fbab901bd0e26c8f3e2fa80cf208e3ba936acb3eef98002459833f96901e1fedb5e97432e05d5ad892beea06a96c059b5c6652a2241bcdaf91ccb4320298868ed3e0929778030e0cce2316b7677cc5574676545aacdef446f078fc08b56415315750ce659fc61db73f633b47a1c874145dd8676e70079ab40587be81c4a9673ded5e61e11c705e45fb4a910a7a1be2b3c3d0af8555a7d9a7aa90d4e4ec0bceb14cdbb1e4c91e379fa6961411139306b6add555734feeb77d51b40e568185b20c141bb4d07b96a1944d187cf8b6019dcdcb27a7309839393e6a63cfaffb9f11d26b503df
e: 0x10001
c: 0x389d979c400a145704d5685bce1f65f642e66c2778e62a7d0519addef8c92d9df42677df805a4e99962b14fb5acd512a7ab65f811842547a1a6670f73b6232e8790887584884caa66dad345c6aeb559402c16990eed47212f0794e11972a1e92030b84663de7cd472ed85c98a6cc42f79f02f7243755f0950894c741740400d0c2c84c6bc1c0380a4ca16eab0ad7ccc3314174c96ecad28bbd364c4ea56e3bc8a7e62c3351307fd1ebe18d3f6e82d778d77e75677a858c4993e4df53ff4d38ce69427b5170631ded7c34d1cc907681a3252d159105891348b4ca84e811611f2f04e6fa2ef6e006e0855f939f41bddcb585777d14942c7f10b2fdd979515cba5f
partial p^q: 0x643e09f2948d2df7b16ffe591ac61e2a57b4cca7ead6a49e10b52593e5f9eb28be9d17eec9f04b6295221968d8bbfb698f87fe6f64b243b5cfd8fcf428b2599bc7fe54dcc695e3fad9
```


<br>

<br>

branch-and-prune the MSB then coppersmith the LSB

Solver:

```python
from Crypto.Util.number import *
from tqdm import tqdm

def solve(tp, tq, cnt):
    print(f"\rSearched index: {cnt}/{known} Queue size: {len(ans)}", end="")
    if cnt == known:
        ans.append((tp, tq))
        return
    b = hint[cnt]
    w = 2**(1024 - cnt - 1)
    tp0, tq0, tp1, tq1 = tp, tq, tp + w, tq + w
    if b == "0": # 00 or 11
        tn0, tm0 = tp0 * tq0, (tp0 + w - 1) * (tq0 + w - 1)
        tn1, tm1 = tp1 * tq1, (tp1 + w - 1) * (tq1 + w - 1)
        if tn0 <= n <= tm0:
            solve(tp0, tq0, cnt+1)
        if tn1 <= n <= tm1:
            solve(tp1, tq1, cnt+1)
    else: # 01 or 10
        tn0, tm0 = tp0 * tq1, (tp0 + w - 1) * (tq1 + w - 1)
        tn1, tm1 = tp1 * tq0, (tp1 + w - 1) * (tq0 + w - 1)
        if tn0 <= n <= tm0:
            solve(tp0, tq1, cnt+1)
        if tn1 <= n <= tm1:
            solve(tp1, tq0, cnt+1)


bits, extra = 1024, 75
known = 1024 - (bits // 2 - extra)

n = 0x46dbd0780b618c8dea0dc6b13a47a5b40bca30b96ed5b15e1be1ffad2fbab901bd0e26c8f3e2fa80cf208e3ba936acb3eef98002459833f96901e1fedb5e97432e05d5ad892beea06a96c059b5c6652a2241bcdaf91ccb4320298868ed3e0929778030e0cce2316b7677cc5574676545aacdef446f078fc08b56415315750ce659fc61db73f633b47a1c874145dd8676e70079ab40587be81c4a9673ded5e61e11c705e45fb4a910a7a1be2b3c3d0af8555a7d9a7aa90d4e4ec0bceb14cdbb1e4c91e379fa6961411139306b6add555734feeb77d51b40e568185b20c141bb4d07b96a1944d187cf8b6019dcdcb27a7309839393e6a63cfaffb9f11d26b503df
e = 0x10001
c = 0x389d979c400a145704d5685bce1f65f642e66c2778e62a7d0519addef8c92d9df42677df805a4e99962b14fb5acd512a7ab65f811842547a1a6670f73b6232e8790887584884caa66dad345c6aeb559402c16990eed47212f0794e11972a1e92030b84663de7cd472ed85c98a6cc42f79f02f7243755f0950894c741740400d0c2c84c6bc1c0380a4ca16eab0ad7ccc3314174c96ecad28bbd364c4ea56e3bc8a7e62c3351307fd1ebe18d3f6e82d778d77e75677a858c4993e4df53ff4d38ce69427b5170631ded7c34d1cc907681a3252d159105891348b4ca84e811611f2f04e6fa2ef6e006e0855f939f41bddcb585777d14942c7f10b2fdd979515cba5f
hint = 0x643e09f2948d2df7b16ffe591ac61e2a57b4cca7ead6a49e10b52593e5f9eb28be9d17eec9f04b6295221968d8bbfb698f87fe6f64b243b5cfd8fcf428b2599bc7fe54dcc695e3fad9
hint <<= (bits // 2 - extra)
hint = format(hint, "01024b")[:known]

ans = []
solve(0, 0, 0)

PR.<x> = PolynomialRing(Zmod(n))
for p_high, _ in tqdm(ans):    
    f = p_high + x
    roots = f.small_roots(beta=0.4, X=2**(1024-known))
    if roots:
        break
p = int(f(roots[0]))
flag = pow(c, pow(e, -1, p-1), p)
print(long_to_bytes(int(flag)))
```

---

Alternative (@goose):

```python
from Crypto.Util.number import long_to_bytes
from tqdm import tqdm

n = 0x46dbd0780b618c8dea0dc6b13a47a5b40bca30b96ed5b15e1be1ffad2fbab901bd0e26c8f3e2fa80cf208e3ba936acb3eef98002459833f96901e1fedb5e97432e05d5ad892beea06a96c059b5c6652a2241bcdaf91ccb4320298868ed3e0929778030e0cce2316b7677cc5574676545aacdef446f078fc08b56415315750ce659fc61db73f633b47a1c874145dd8676e70079ab40587be81c4a9673ded5e61e11c705e45fb4a910a7a1be2b3c3d0af8555a7d9a7aa90d4e4ec0bceb14cdbb1e4c91e379fa6961411139306b6add555734feeb77d51b40e568185b20c141bb4d07b96a1944d187cf8b6019dcdcb27a7309839393e6a63cfaffb9f11d26b503df
e = 0x10001
c = 0x389d979c400a145704d5685bce1f65f642e66c2778e62a7d0519addef8c92d9df42677df805a4e99962b14fb5acd512a7ab65f811842547a1a6670f73b6232e8790887584884caa66dad345c6aeb559402c16990eed47212f0794e11972a1e92030b84663de7cd472ed85c98a6cc42f79f02f7243755f0950894c741740400d0c2c84c6bc1c0380a4ca16eab0ad7ccc3314174c96ecad28bbd364c4ea56e3bc8a7e62c3351307fd1ebe18d3f6e82d778d77e75677a858c4993e4df53ff4d38ce69427b5170631ded7c34d1cc907681a3252d159105891348b4ca84e811611f2f04e6fa2ef6e006e0855f939f41bddcb585777d14942c7f10b2fdd979515cba5f
leak = 0x643e09f2948d2df7b16ffe591ac61e2a57b4cca7ead6a49e10b52593e5f9eb28be9d17eec9f04b6295221968d8bbfb698f87fe6f64b243b5cfd8fcf428b2599bc7fe54dcc695e3fad9

BITS = 1024
EXTRA_BITS = 75

KNOWN_BITS = BITS // 2 + EXTRA_BITS
MISSING_BITS = BITS // 2 - EXTRA_BITS

xor_bits = f"{leak << MISSING_BITS:b}".zfill(BITS)

candidates = []

def extend_msb(p_bits: str, q_bits: str, depth: int) -> None:
    if depth == KNOWN_BITS:
        p_candidate = int(p_bits + '0' * (BITS - depth), 2)
        q_candidate = int(q_bits + '0' * (BITS - depth), 2)
        if p_candidate * q_candidate <= n:
            candidates.append(p_candidate)
        return

    bit = xor_bits[depth]
    # XOR constraint: p_i XOR q_i = bit
    bit_options = [('0', '1'), ('1', '0')] if bit == '1' else [('0', '0'), ('1', '1')]

    for bit_p, bit_q in bit_options:
        extended_p = p_bits + bit_p
        extended_q = q_bits + bit_q

        min_p = int(extended_p + '0' * (BITS - depth - 1), 2)
        min_q = int(extended_q + '0' * (BITS - depth - 1), 2)
        max_p = int(extended_p + '1' * (BITS - depth - 1), 2)
        max_q = int(extended_q + '1' * (BITS - depth - 1), 2)

        if min_p * min_q <= n <= max_p * max_q:
            extend_msb(extended_p, extended_q, depth + 1)

extend_msb("1", "1", 1)

print("[*] Starting Coppersmith attack...")
for p_high in tqdm(candidates, leave=False):
    PR = PolynomialRing(Zmod(n), 'x')
    x = PR.gen()
    f = p_high + x

    roots = f.small_roots(X=1 << MISSING_BITS, beta=0.45)
    if roots:
        x0 = int(roots[0])
        p = int(f(x0))
        if n % p == 0:
            q = n // p
            phi = (p-1)*(q-1)
            d = pow(e, -1, phi)
            m = int(pow(c, d, n))
            flag = long_to_bytes(m)
            tqdm.write(f"[+] Found p: {p}")
            tqdm.write(f"[+] Flag: {flag}")
            break
```


