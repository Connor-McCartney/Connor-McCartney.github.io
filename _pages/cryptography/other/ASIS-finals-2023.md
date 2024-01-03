---
permalink: /cryptography/other/ASIS-finals-2023
title: ASIS finals 2023
---

<br>
<br>

[Challenge Files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2023/ASIS-finals)

<br>

# tricare

<br>

We can simplify r using a lot of [product-to-sum](https://andymath.com/wp-content/uploads/2019/09/Product-and-Sum-Formulas-e1567457862597.jpg) substitutions:

$$r = 20 \sin^3(m)\cos^3(m) - 6\sin(m)\cos(m)(\sin^4(m) + \cos^4(m))$$

$$= 20 \cdot\sin(m)\cos(m) \cdot \sin(m)\sin(m) \cdot \cos(m)\cos(m) - 6 \cdot \sin(m)\cos(m) \cdot ((\sin(m)\sin(m))^2 + (\cos(m)\cos(m))^2)$$

$$= 2 \cdot\sin(m)\cos(m) \cdot \left(10 \cdot \sin(m)\sin(m) \cdot \cos(m)\cos(m) - 3 \cdot ((\sin(m)\sin(m))^2 + (\cos(m)\cos(m))^2)\right)$$

$$= 2 \cdot \frac{\sin(2m)}{2} \cdot \left(10 \cdot  \frac{1 - \cos(2m)}{2} \cdot \frac{\cos(2m) + 1}{2} - 3 \cdot \left(\left(\frac{1 - \cos(2m)}{2}\right)^2 + \left(\frac{\cos(2m) + 1}{2}\right)^2\right) \right)$$

$$= \sin(2m) \cdot \left(\frac{10}{4} \cdot  (1 - \cos^2(2m)) - \frac{3}{4} \cdot (2 + 2\cos^2(2m))  \right)$$

$$=\sin(2m) \cdot \left(   \frac{10}{4} - \frac{10}{4}\cos^2(2m) - \frac{6}{4} - \frac{6}{4}\cos^2(2m)  \right)$$

$$=\sin(2m) \cdot ( 1  - 4\cos^2(2m) )$$

$$= \sin(2m) - 4\sin(2m)\frac{\cos(4m)+1}{2}$$

$$= -2\sin(2m)\cos(4m) -  \sin(2m)$$

$$= -2\frac{\sin(6m) - \sin(2m)}{2} -  \sin(2m)$$

$$= -\sin(6m)$$

<br>

Sub r in and we have:

$$t = \frac{1 - \cos(6m) + \text{seed} \cdot\sin(6m)}{\sin(6m) + \text{seed} \cdot (\cos(6m) + 1)}$$

[Yeet that into wolfram alpha](https://www.wolframalpha.com/input?i=%281+-+cos%286x%29+%2B+y+*+sin%286x%29%29+%2F+%28sin%286x%29+%2B+y+*+%28cos%286x%29%2B1%29%29) and we get:

$$t = \tan(3m)$$

<br>

Now sub t into s:

$$s = \frac{(\tan(3m))^3 - 3(\tan(3m))}{1 - 3(\tan(3m))^2}$$

<br>

Again, [yeet into wolfram alpha](https://www.wolframalpha.com/input?i=%28%28tan%283x%29%29%5E3+-+3%28tan%283x%29%29%29+%2F+%281+-+3%28tan%283x%29%5E2%29%29) and we get:

$$s = -\tan(9m)$$

<br>

Rearranging:

$$\tan(-9m) = s$$

$$-9m = \arctan(s) + k\pi$$

$$0 = \arctan(s) + k\pi + 9m$$

<br>

Turning into vector equations for LLL:

$$1 \begin{bmatrix} \arctan(s) \\ 1 \\ 0\end{bmatrix} + k \begin{bmatrix} \pi \\ 0 \\ 0\end{bmatrix} + m \begin{bmatrix} 9 \\ 0 \\ 1 \end{bmatrix}   = \begin{bmatrix} 0 \\ 1 \\ m \end{bmatrix}$$
