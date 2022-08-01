---
permalink: /cryptography/other/Lighthouse-UACTF-2022
title: Lighthouse - UACTF 2022
---

<br>

[Challenge](https://github.com/Connor-McCartney/CTF_Files/tree/main/2022/UACTF)


Check out <https://github.com/nneonneo/pwn-stuff/blob/36f0ecd80b05859acca803d4ddfb53454b448329/math/solvelinmod.py>!

Each wheel turned each other wheel a certain number of times. JS code in /dist

Have to find minimum turns for each wheel to get goal = 8, 11, 22, 4, 14, 26, 3, 21

So basically solve 8 linear equations mod 29.

```py
import fpylll

#https://github.com/nneonneo/pwn-stuff/blob/36f0ecd80b05859acca803d4ddfb53454b448329/math/solvelinmod.py
def solve_linear_mod(equations, bounds, guesses=None):
    vars = list(bounds)
    if guesses is None:
        guesses = {}
    NR = len(equations)
    NV = len(vars)
    B = fpylll.IntegerMatrix(NR+NV, NR+NV)
    Y = [None] * (NR + NV)
    nS = 1
    for var in vars:
        nS = max(nS, int(bounds[var]).bit_length())
    S = (1 << (nS + (NR + NV + 1)))
    scales = {}
    for vi, var in enumerate(vars):
        scale = S >> (int(bounds[var]).bit_length())
        scales[var] = scale
        # Fill in vars block of B
        B[NR + vi, vi] = scale
        Y[NR + vi] = guesses.get(var, int(bounds[var]) >> 1) * scale
    for ri, (rel, m) in enumerate(equations):
        op = rel.operator()
        if op is not operator.eq:
            raise TypeError('relation %s: not an equality relation' % rel)
        expr = (rel - rel.rhs()).lhs().expand()
        for var in expr.variables():
            if var not in bounds:
                raise ValueError('relation %s: variable %s is not bounded' % (rel, var))
        coeffs = []
        for vi, var in enumerate(vars):
            if expr.degree(var) >= 2:
                raise ValueError('relation %s: equation is not linear in %s' % (rel, var))
            coeff = expr.coefficient(var)
            if not coeff.is_constant():
                raise ValueError('relation %s: coefficient of %s is not constant (equation is not linear)' % (rel, var))
            if not coeff.is_integer():
                raise ValueError('relation %s: coefficient of %s is not an integer' % (rel, var))
            B[ri, vi] = (int(coeff) % m) * S
        B[ri, NV + ri] = m * S
        const = expr.subs({var: 0 for var in vars})
        if not const.is_constant():
            raise ValueError('relation %s: failed to extract constant' % rel)
        if not const.is_integer():
            raise ValueError('relation %s: constant is not integer' % rel)
        Y[ri] = (int(-const) % m) * S
    Bt = B.transpose()
    lll = fpylll.LLL.reduction(Bt)
    result = fpylll.CVP.closest_vector(Bt, Y)
    if list(map(int, result[:NR])) != list(map(int, Y[:NR])):
        raise ValueError("CVP returned an incorrect result: input %s, output %s (try increasing your bounds?)" % (Y, result))
    res = {}
    for vi, var in enumerate(vars):
        aa = result[NR + vi] // scales[var]
        bb = result[NR + vi] % scales[var]
        if bb:
            warnings.warn("CVP returned suspicious result: %s=%d is not scaled correctly (try adjusting your bounds?)" % (var, result[NR + vi]))
        res[var] = aa
    return res


p = 29
n = [var('n%d' % i) for i in range(1, 9)]
bounds = bounds = {n[i]:p for i in range(8)}
print(solve_linear_mod([
    (8  == 18 + n1*1  + n2*46 + n3*48 + n4*40 + n5*48 + n6*11 + n7*19 + n8*12, p), 
    (11 == 12 + n1*6  + n2*1  + n3*30 + n4*11 + n5*49 + n6*9  + n7*34 + n8*10, p), 
    (22 == 4  + n1*28 + n2*14 + n3*1  + n4*16 + n5*26 + n6*13 + n7*23 + n8*36, p), 
    (4  == 8  + n1*40 + n2*25 + n3*47 + n4*1  + n5*16 + n6*3  + n7*10 + n8*6 , p), 
    (14 == 17 + n1*16 + n2*44 + n3*46 + n4*50 + n5*1  + n6*11 + n7*31 + n8*19, p), 
    (26 == 2  + n1*42 + n2*17 + n3*27 + n4*12 + n5*6  + n6*1  + n7*27 + n8*24, p), 
    (3  == 15 + n1*46 + n2*27 + n3*20 + n4*27 + n5*16 + n6*10 + n7*1  + n8*8 , p), 
    (21 == 8  + n1*37 + n2*27 + n3*25 + n4*26 + n5*2  + n6*35 + n7*32 + n8*1 , p)],
    bounds))

"""
{n1: 24, n2: 26, n3: 25, n4: 28, n5: 12, n6: 1, n7: 27, n8: 4}

Use this to convert the minimum number of turns to the flag
0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28
A B C D E F G H I J K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z  _  !  *

UACTF{Y_Z*MB!E}
"""
```
