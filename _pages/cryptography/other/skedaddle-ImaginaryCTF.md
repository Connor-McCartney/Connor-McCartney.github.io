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

