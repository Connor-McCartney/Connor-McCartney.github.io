---
permalink: /cryptography/small-roots/notes
title: Notes
---


<br>


<https://www.di.ens.fr/~fouque/ens-rennes/coppersmith.pdf>

Disclaimer: very simplified


First a look at 'shift-polynomials' (it seems you just multiply by some power of x):

```python
p = random_prime(2**1024)
q = random_prime(2**1024)
n = p*q

# f(x) = x^3 + Ax^2 + Bx + C 
A, B = [randint(1, n) for _ in range(2)]
x0 = randint(0, 2**64)
C = randint(0, n)*n - (x0^3 + A*x0^2 + B*x0)

r0 = 1
r1 = x0
r2 = x0^2
r3 = x0^3
r4 = x0^4
#           x^3 + A*x^2 +B*x  + C*1
assert 0 == (r3 + A*r2 + B*r1 + C*r0) % n
assert 0 == (r4 + A*r3 + B*r2 + C*r1) % n # 'shifted'!
```

Next, an important note of the paper is some extra polynomials to use. For the solution/root x0, some extra polynomials are:

$$
x_0^i \cdot f(x_0)^j \equiv 0 \ \  (\text{mod } N^j)
$$

<br>


Let's try get some intuition by following a univariate case, say 

f(x) = x^2 + ax + b


```python
p = random_prime(2**1024)
q = random_prime(2**1024)
n = p*q

# f(x) = x^2 + ax + b
a = randint(1, n)
x0 = randint(0, 2**64)
b = randint(0, n)*n - (x0^2 + a*x0)

PR.<x> = PolynomialRing(Zmod(n))
f = x^2 + a*x + b
assert f(x=x0) == 0
print(f.small_roots(X=2**64))
```

<br>

Now let's do this manually instead of relying on sage's small_roots function!!


Original polynomial (i=0, j=1):

x^2 + ax + b

We can shift it once (i=1, j=1):

x^3 + ax^2 + bx

We can square the original polynomial (i=0, j=2):

x^4 + cx^3 + dx^2 + ex + f

and we can also shift this one (i=1, j=2):

x^5 + cx^4 + dx^3 + ex^2 + fx

We could continue but let's stop here with 4 polynomials. 

Now build the lattice! which lets us recover x, x^2, x^3, x^4, and x^5

$$
1 \begin{bmatrix}1  \\ 0 \\ 0 \\ 0 \\ 0 \\ 0 \\ b \\ 0 \\ f \\ 0 \end{bmatrix} + 
x \begin{bmatrix}0    \\ 1 \\ 0 \\ 0 \\ 0 \\ 0 \\ a \\ b \\ e \\ f\end{bmatrix}  + 
x^2 \begin{bmatrix}0  \\ 0 \\ 1 \\ 0 \\ 0 \\ 0 \\ 1 \\ a \\ d \\ e\end{bmatrix}  +
x^3 \begin{bmatrix}0  \\ 0 \\ 0 \\ 1 \\ 0 \\ 0 \\ 0 \\ 1 \\ c \\ d\end{bmatrix} + 
x^4 \begin{bmatrix}0  \\ 0 \\ 0 \\ 0 \\ 1 \\ 0 \\ 0 \\ 0 \\ 1 \\ c\end{bmatrix} + 
x^5 \begin{bmatrix}0  \\ 0 \\ 0 \\ 0 \\ 0 \\ 1 \\ 0 \\ 0 \\ 0 \\ 1\end{bmatrix} +
y_0 \begin{bmatrix}0  \\ 0 \\ 0 \\ 0 \\ 0 \\ 0 \\ n \\ 0 \\ 0 \\ 0\end{bmatrix} + 
y_1 \begin{bmatrix}0  \\ 0 \\ 0 \\ 0 \\ 0 \\ 0 \\ 0 \\ n \\ 0 \\ 0\end{bmatrix} + 
y_2 \begin{bmatrix}0  \\ 0 \\ 0 \\ 0 \\ 0 \\ 0 \\ 0 \\ 0 \\ n^2 \\ 0\end{bmatrix} + 
y_3 \begin{bmatrix}0  \\ 0 \\ 0 \\ 0 \\ 0 \\ 0 \\ 0 \\ 0 \\ 0 \\ n^2\end{bmatrix}  
= \begin{bmatrix}1  \\ x \\ x^2 \\ x^3 \\ x^4 \\ x^5 \\ 0 \\ 0 \\ 0 \\ 0\end{bmatrix}
$$


```python
p = random_prime(2**1024)
q = random_prime(2**1024)
n = p*q


# f(x) = x^2 + ax + b
a = randint(1, n)
X = 2**800
x0 = randint(0, X)
b = randint(0, n)*n - (x0^2 + a*x0)

PR.<x> = PolynomialRing(Zmod(n))
f = x^2 + a*x + b
assert f(x=x0) == 0
print(f.small_roots(X=X))


PR.<x> = PolynomialRing(ZZ)
f = x^2 + a*x + b
f, e, d, c, _ = (f^2).coefficients()
assert (x0^4 + c*x0^3 + d*x0^2 + e*x0 + f) % n^2 == 0

M = Matrix(QQ, [
    [1, 0, 0, 0, 0, 0, b, 0, f,   0  ],
    [0, 1, 0, 0, 0, 0, a, b, e,   f  ],
    [0, 0, 1, 0, 0, 0, 1, a, d,   e  ],
    [0, 0, 0, 1, 0, 0, 0, 1, c,   d  ],
    [0, 0, 0, 0, 1, 0, 0, 0, 1,   c  ],
    [0, 0, 0, 0, 0, 1, 0, 0, 0,   1  ],
    [0, 0, 0, 0, 0, 0, n, 0, 0,   0  ],
    [0, 0, 0, 0, 0, 0, 0, n, 0,   0  ],
    [0, 0, 0, 0, 0, 0, 0, 0, n^2, 0  ],
    [0, 0, 0, 0, 0, 0, 0, 0, 0,   n^2],
])


W = diagonal_matrix(QQ, [1, 1/X, 1/X^2, 1/X^3, 1/X^4, 1/X^5] + [1, 1, 1, 1])
M = (M*W).LLL() / W
for row in M:
    if list(row[-4:]) == [0, 0, 0, 0]:
        print(row[1])
```
