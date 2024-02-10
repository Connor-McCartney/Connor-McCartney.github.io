---
permalink: /cryptography/rsa/L4ugh-0xl4ughCTF-2024
title: L4ugh - 0xl4ughCTF 2024
---

<br>

[Challenge Files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2024/0xL4ugh/L4ugh)

<br>

A nice challenge written by my friend mindflayer and Bebo!

This was a 3-part challenge, finding d_good, finding d_evil, and a CBC bit flipping attack.

To find d_good you can send the biggest number allowed then divide by it, negating <br>
the comparatively small error constant added.

Finding d_evil was interesting. We have pairs of n and e generated with the same d.

```python
assert d*e % phi == 1 
k = (e*d-1)//phi
assert e*d == 1 + k*phi
assert e*d == 1 + k*(N-p-q+1)
assert e*d - k*N - (1 + k*(-p-q+1)) == 0
# let x = (1 + k*(-p-q+1))
```

Only two pairs are needed to find d:

$$e_1\cdot d - k_1 \cdot N_1 = x_1$$

$$e_2\cdot d - k_2 \cdot N_2 = x_2$$

Rewriting as vector equations for LLL:

$$d \begin{bmatrix}e_2 \\ e_1 \\ 1\end{bmatrix} - k_1 \begin{bmatrix}0\\ N_1 \\ 0\end{bmatrix} - k_2 \begin{bmatrix}N_2 \\ 0 \\ 0\end{bmatrix} = \begin{bmatrix}x_1 \\ x_2 \\ d\end{bmatrix}$$

