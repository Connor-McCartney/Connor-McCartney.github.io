---
permalink: /misc/linear-algebra
title: Linear Algebra Notes
---


<br>


# 1. Solutions of first order ODEs


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


Final answer:

$y = \frac{1}{27} (x+3)^3$

<br> <br> <br>


2: (Separable)

<https://www.wolframalpha.com/input?key=&i=%28dy%29%2F%28dx%29+%3D+%283x%5E2+%2B+4x+%2B+2%29+%2F+%282%28y-1%29%29%2C+y%280%29%3D1>

$\frac{dy}{dx} = \frac{3x^2 + 4x + 2}{2(y-1)}, \ y(0) = 1$


Final answer: 

$y = 1 \pm \sqrt{x^3 + 2x^2 + 2x}, \ \ x > 0$
