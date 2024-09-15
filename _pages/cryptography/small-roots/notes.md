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


<br>
<br>


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

---

<br>

See also ["Finding Small Roots of Univariate Modular Equations Revisited - Nicholas Howgrave-Graham, 1997"](https://sci-hub.se/10.1007/bfb0024458)

Let's look at their example for the difference between Coppersmith's original method and the Howgrave-Graham reformulation.

Their example polynomial is x^2 + 14x + 19 = 0 (mod 35) with solution x0=3.

x f(x) = x^3 + 14x^2 + 19x

f(x)^2 = x^4 + 28x^3 + 234x^2 + 532x + 361

x f(x)^2 = x^5 + 28x^4 + 234x^3 + 532x^2 + 361x


<br>

Note that copying the previous approach exactly won't give the target vector (1, x, x^2, x^3, x^4, x^5, 0, 0, 0, 0) 

because it will overflow above the modulus. Instead, it will contain some constants we can use to make a new poly over integers. 

Some code to supplement the paper:

```python
# Coppersmith's original approach

n = 35
a = 14
b = 19
c = 28
d = 234
e = 532
f = 361
X = 2

M = Matrix([
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

H1_inv = Matrix([
    [1, 0, 0, 0, 0, 0, b, 0, f,   0  ],
    [0, 1, 0, 0, 0, 0, a, b, e,   f  ],
    [0, 0, 0, 0, 0, 0, 1, a, d,   e  ],
    [0, 0, 0, 0, 0, 0, 0, 1, c,   d  ],
    [0, 0, 0, 0, 0, 0, 0, 0, 1,   c  ],
    [0, 0, 0, 0, 0, 0, 0, 0, 0,   1  ],
    [0, 0, 1, 0, 0, 0, n, 0, 0,   0  ],
    [0, 0, 0, 1, 0, 0, 0, n, 0,   0  ],
    [0, 0, 0, 0, 1, 0, 0, 0, n^2, 0  ],
    [0, 0, 0, 0, 0, 1, 0, 0, 0,   n^2],
])

H1 = H1_inv.inverse()
M_bar = H1*M
print(M_bar); print()

M_bar = M_bar[5::-1, 5::-1]
print(M_bar); print()

W = diagonal_matrix(QQ, [1, X, X^2, X^3, X^4, X^5])
M_bar *= W

B2 = M_bar.LLL()

H2 = B2 * M_bar.inverse()
H2_inv = H2.inverse()
# most of the columns in the paper are the same, just a different order
# cause of varying LLL internals/implementations probably
print(H2_inv); print() 



var('x')
p = x^2 + a*x + b
cx = vector([1, x, -p/n, -(x*p)/n, (-p^2)/(n^2), (-x*p^2)/(n^2)])
for col in H2_inv.T:
    col = col[::-1]
    f = cx*col #* n^2 
    try:
        for root, _ in f.roots():
            if root.is_integer():
                print(f'{col = }')
                print(f'{root = }')
    except RuntimeError:
        # no roots
        pass
```

<br>

```python
# Howgrave-Graham approach

n = 35
a = 14
b = 19
c = 28
d = 234
e = 532
f = 361
X = 2

M = Matrix([
    [n^2, 0,   0,   0, 0, 0],
    [0,   n^2, 0,   0, 0, 0],
    [b*n, a*n, n,   0, 0, 0],
    [0,   b*n, a*n, n, 0, 0],
    [f,   e,   d,   c, 1, 0],
    [0,   f,   e,   d, c, 1]
])

W = diagonal_matrix([1, X, X^2, X^3, X^4, X^5])
M = (M*W).LLL() / W
for row in M:
    r0, r1, r2, r3, r4, r5 = row[::-1]
    var('x')
    f = r5*x^5 + r4*x^4 + r3*x^3 + r2*x^2 + r1*x + r0
    try:
        for root, _ in f.roots():
            if root.is_integer():
                print(f'{root = }')
    except:
        pass
```
