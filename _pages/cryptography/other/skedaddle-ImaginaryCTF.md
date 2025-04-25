---
permalink: /cryptography/other/skedaddle-ImaginaryCTF
title: skedaddle - Imaginary CTF
---

<br>


Challenge:

```c
#include <stdint.h>
#include <stdio.h>

uint64_t fmix64(uint64_t k) {
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccd;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53;
    k ^= k >> 33;
    return k;
}

int main() {
    uint64_t i = 1;
    while (fmix64(i) != i) ++i;
    printf("ictf{%lu}\n", i);
}
```

<br>


Solve:



```python
def f(k):
    k2 = k ^ (k>>33)
    k3 = k2 * 0xff51afd7ed558ccd % 2**64
    k4 = k3 ^ (k3>>33)
    # we'll calculate lsb of k4 at this point
    k5 = k4 * 0xc4ceb9fe1a85ec53 % 2**64
    k6 = k5 ^ (k5>>33)
    return k6
```

<br>

```python
def f(k):
    k2 = k ^ (k>>33)
    k3 = k2 * 0xff51afd7ed558ccd % 2**64
    k4 = k3 ^ (k3>>33) # midpoint
    k5 = k4 * 0xc4ceb9fe1a85ec53 % 2**64
    k6 = k5 ^ (k5>>33)

    k2_lsb = k2 % 2**33
    k4_lsb = k4 % 2**33
    k5_lsb = k5 % 2**33

    # from the top:
    assert k4_lsb == ((k2_lsb * 0xff51afd7ed558ccd) ^ (k3>>33)) % 2**33

    # from the bottom:
    assert k4_lsb == k5_lsb * pow(0xc4ceb9fe1a85ec53, -1, 2**64) % 2**33

    assert k5_lsb == k2_lsb
    assert k3 >> 33 == k4 >> 33

    # rearrange bottom:
    assert k5_lsb == k4_lsb * 0xc4ceb9fe1a85ec53 % 2**33

    # sub into top:
    assert k4_lsb == ((k4_lsb * 0xc4ceb9fe1a85ec53 * 0xff51afd7ed558ccd) ^ (k4>>33)) % 2**33
    assert (k4>>33) == k4_lsb ^ (k4_lsb * 0xc4ceb9fe1a85ec53 * 0xff51afd7ed558ccd % 2**33)
    assert (k4>>33) == k4_lsb ^ (k4_lsb * 0xc4ceb9fe1a85ec53 * 0xff51afd7ed558ccd) & 0x1ffffffff



f(13621417624426829092)
```


So you can brute k4_lsb (2^33) which gives you k4_msb


<br>

```c
#include <stdio.h>
#include <stdint.h>

int main() {
    for (uint64_t k4_lsb=1; k4_lsb<(1UL<<33); k4_lsb++) {
        uint64_t k4_msb = (k4_lsb ^ (k4_lsb*0xc4ceb9fe1a85ec53*0xff51afd7ed558ccd)) & 0x1ffffffff;
        uint64_t k4 = k4_msb * (1UL<<33) + k4_lsb;

        uint64_t k5 = k4 * 0xc4ceb9fe1a85ec53;
        uint64_t k6 = k5 ^ (k5 >> 33);

        uint64_t k3 = k4 ^ (k4 >> 33);
        uint64_t k2 = k3 * 5725274745694666757;
        uint64_t k1 = k2 ^ (k2 >> 33);

        if (k1 == k6) {
            printf("ictf{%lu}\n", k1);
        }
    }
}
```

<br>



flag: `ictf{13621417624426829092}`








<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

---

<br>

<br>

<br>


# skedaddle revenge

Challenge:

```python
#!/usr/local/bin/python3
def fmix128(k):
    k ^= k >> 65
    k *= 0xff51afd7ed558ccdff51afd7ed558ccd
    k &= 0xffffffffffffffffffffffffffffffff
    k ^= k >> 65
    k *= 0xc4ceb9fe1a85ec53c4ceb9fe1a85ec53
    k &= 0xffffffffffffffffffffffffffffffff
    k ^= k >> 65
    return k

k = int(input('k: '), 0)
if 0 < k < 2**128 and k == fmix128(k):
    print('ictf{REDACTED}')
else:
    print('WRONG')
```

<br>

Solve:




<br>

Consider

```python
C = pow(0xff51afd7ed558ccd * 0xc4ceb9fe1a85ec53, -1, 2**64)
(x ^ (x>>33) ^ (x*C)) % 2**64 == 0
```

