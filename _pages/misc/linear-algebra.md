---
permalink: /misc/linear-algebra
title: Linear Algebra Notes
---


<br>


# 1. Solutions of first order ODEs

<br>

Directly integrable:

$\frac{dy}{dx} = f(x)$

$y(x) = \int{f(x)} \ dx + c$

<br>


Seperable:

$\frac{dy}{dx} = f(x) g(y)$

$\int{ \frac{1}{g(y)} \frac{dy}{dx} } \ dx = \int{f(x)} \ dx$

$\int{ \frac{1}{g(y)} \ dy } = \int{f(x)} \ dx \ \ \text{(implicit solution)}$

<br>


Linear:

$\frac{dy}{dx} = q(x) - p(x) y$

Use an integrating factor, I, chosen carefully such that the LHS is reduced with the product rule.

There is once choice for I that always works:  $I = e^{\int{p} \ dx}$

$I \frac{dy}{dx} + I \cdot p(x) \cdot y = I \cdot q(x)$

$\frac{d}{dx}(I \cdot y) = I \cdot q(x)$

$I \cdot y = \int{I \cdot q(x)} \ dx$



<br> <br> <br>

Exercises:

1: (Seperable)

<https://www.wolframalpha.com/input?key=&i=%28dy%29%2F%28dx%29+%3D+y%5E%282%2F3%29%2C+y%280%29%3D1>

$\frac{dy}{dx} = y^{\frac{2}{3}}, \ y(0) = 1$

We have f(x) = 1 and g(y) = $y^{\frac{2}{3}}$

$\int{ \frac{1}{g(y)} \ dy } = \int{f(x)} \ dx$

$\int{  \frac{1}{ y^{\frac{2}{3}} }  } \ dy = x + c$

$\int{  y^{-\frac{2}{3}}   } \ dy = x + c$

$3 y^{1/3}= x + c$

When x=0, y=1

$3 \cdot 1^{1/3}= 0 + c$

$\therefore c=3$

$y^{1/3} = \frac{1}{3} (x + 3)$

$y = \frac{1}{27} (x + 3)^3$


<br> <br> <br>


2: (Separable)

<https://www.wolframalpha.com/input?key=&i=%28dy%29%2F%28dx%29+%3D+%283x%5E2+%2B+4x+%2B+2%29+%2F+%282%28y-1%29%29%2C+y%280%29%3D1>

$\frac{dy}{dx} = \frac{3x^2 + 4x + 2}{2(y-1)}, \ y(0) = 1$

We have f(x) = $3x^2 + 4x + 2$ and g(y) = $\frac{1}{2(y-1)}$

$\int{ \frac{1}{g(y)} \ dy } = \int{f(x)} \ dx$

$\int{ 2y-2 \ dy } = \int{3x^2 + 4x + 2} \ dx$

$y^2 - 2y = x^3 + 2x^2 + 2x + c$

When x=0, y=1

$1^2 - 2(1) = 0^3 + 2(0)^2 + 2(0) + c$

$\therefore c = -1$

$y^2 - 2y = x^3 + 2x^2 + 2x -1$

$(y-1)^2 = x^3 + 2x^2 + 2x$

$y = 1 \pm \sqrt{x^3 + 2x^2 + 2x}, \ x > 0$

<br><br><br>

3: (Linear)

$y' + 2y = 4$, $y'(0) = 4$

$y' = 4 - 2y$

$q(x) = 4, p(x) = 2$

$I = e^{\int{p} \text{ } dx} = e^{2x}$

$e^{2x} y = \int{4e^{2x}} \text{ }dx$

$e^{2x} y = 4(\frac{e^{2x}}{2}) + c$

$y = 2 + ce^{-2x}$

$y(0) = 4, c=2$

$\therefore y = 2 + 2e^{-2x}$



<br>
<br>

# 2. Successive approximations


It is always possible to apply a variable shift so that the IVP can be written as

$\frac{dy}{dx} = f(x,y), \ y(0) = 0$  (1)

<br>

E.g. $y' = 2(x-1)(y-1), \ y(1) = 2$

$\bar{x} = x-1, \bar{y} = y-2$

$\frac{d \bar{y}}{d \bar{x}} = 2 \bar{x}(\bar{y} + 1), \ \bar{y}(0) = 0$

<br>
<br>
<br>

Let $y = \phi (x)$ be a solution to the IVP (1), then 

$\phi(x) = \int_0^x{f(t, \phi (t))} dt$  (2)

(1) and (2) are equivalent, so a solution to one is a solution to the other.

Now consider

$\phi_{n+1}(x) = \int_0^x{f(t, \phi_n (t))} dt$  (3)

If there exists some k such that $\phi_{k+1}(x) = \phi_{k}(x)$ then $\phi_{k}(x)$ is a solution of (2) and hence (1).
Generally this does not occur, but we may instead consider limit functions.

<br>
<br>
<br>

# 3. Exact 1st order ODEs


Test for exactness:

$P(x,y) + Q(x,y) \frac{dy}{dx} = 0$  is an exact ODE iff $\frac{\partial P}{\partial y} = \frac{\partial Q}{\partial x}$ everywhere in the region.

<br>
<br>

Exercises:

1:
<https://www.wolframalpha.com/input?key=&i=%5Ccos%28x%2By%29+dx+%2B+%283y%5E2+%2B+2y+%2B+%5Ccos%28x%2By%29%29+dy+%3D+0>

$\cos(x+y) dx + (3y^2 + 2y + \cos(x+y)) dy = 0$

Determine if it is exact, and solve if so.

$\frac{\cos(x+y) dx}{dx} + (3y^2 + 2y + \cos(x+y)) \frac{dy}{dx} = 0$

$\cos(x+y) + (3y^2 + 2y + \cos(x+y)) \frac{dy}{dx} = 0$

We have P = $\cos(x+y)$ and Q = $3y^2 + 2y + \cos(x+y)$

$\frac{\partial P}{\partial y} = \frac{\partial Q}{\partial x} = -sin(x+y)$

So it is exact. Then we seek f(x,y) such that:

(1) $\frac{\partial f}{\partial x} = P$    ->   $f = \int{\cos(x+y)} dy = \sin(x+y) + g(y)$ -> $\frac{\partial f}{\partial y} = \cos(x+y) + \frac{dg(y)}{dy}$

(2) $\frac{\partial f}{\partial y} = Q$

Compare (1) with (2) to solve $\frac{dg(y)}{dy}$ and then $g(y)$

$\cos(x+y) + \frac{dg(y)}{dy} = Q$

$\cos(x+y) + \frac{dg(y)}{dy} = 3y^2 + 2y + \cos(x+y)$

$\frac{dg(y)}{dy} = 3y^2 + 2y$

$g(y) = \int{3y^2 + 2y} \ dy$

$g(y) = y^3 + y^2 + c$

$\therefore f(x,y) = \sin(x+y) + y^3 + y^2 = c$
