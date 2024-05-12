---
permalink: /cryptography/rsa/ReallyComplexProblems-SDCTF-2024
title: ReallyComplexProblems - SDCTF 2024
---

<br>

[Challenge Files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2024/SDCTF/ReallyComplexProblems)

<br>

Given Ni, Nr, MSB of pi and MSB of pr, we have to factor N_. 

```python
    Nr = int(N.real)
    Ni = int(N.imag)
    pr = int(p.real)
    pi = int(p.imag)
    qr = int(q.real)
    qi = int(q.imag)

    assert Nr == pr*qr - pi*qi
    assert Ni == pr*qi + pi*qr

    p_ = pi**2 + pr**2
    q_ = qi**2 + qr**2
    N_ = Ni**2 + Nr**2
    assert is_prime(p_) and is_prime(q_)
    assert p_ * q_ == N_
```


