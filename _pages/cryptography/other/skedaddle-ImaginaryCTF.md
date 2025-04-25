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

Consider:

```python
C = pow(0xff51afd7ed558ccd * 0xc4ceb9fe1a85ec53, -1, 2**63)
(x ^ (x>>33) ^ (x*C)) % 2**63 == 0
```

Rearrange:



brute x:

