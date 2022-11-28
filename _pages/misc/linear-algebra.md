---
permalink: /misc/linear-algebra
title: Linear Algebra Notes
---


<br>


# 1. Solutions of first order ODEs


Directly integrable:

$\frac{dy}{dx} = f(x)$


Seperable:

$\frac{dy}{dx} = f(x) g(y)$

Linear:

$\frac{dy}{dx} = q(x) - p(x) y$



<br> <br> <br>



Directly integrable:

$\frac{dy}{dx} = f(x)$

$y(x) = \int{f(x)} \ dx + c$



Seperable:

$\frac{dy}{dx} = f(x) g(y)$

$$


Linear:

$\frac{dy}{dx} = q(x) - p(x) y$



<br> <br> <br>

Exercises:

1: (Seperable)

<https://www.wolframalpha.com/input?key=&i=%28dy%29%2F%28dx%29+%3D+y%5E%282%2F3%29%2C+y%280%29%3D1>

$\frac{dy}{dx} = y^{\frac{2}{3}}, \ y(0) = 1$

$y = \int{y^{\frac{2}{3}}} \ dx$


Final answer:

$y = \frac{1}{27} (x+3)^3$

<br> <br> <br>


2: (Separable)

<https://www.wolframalpha.com/input?key=&i=%28dy%29%2F%28dx%29+%3D+%283x%5E2+%2B+4x+%2B+2%29+%2F+%282%28y-1%29%29%2C+y%280%29%3D1>

$\frac{dy}{dx} = \frac{3x^2 + 4x + 2}{2(y-1)}, \ y(0) = 1$


Final answer: 

$y = 1 \pm \sqrt{x^3 + 2x^2 + 2x}, \ \ x > 0$
