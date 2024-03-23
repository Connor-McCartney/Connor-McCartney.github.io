---
permalink: /cryptography/other/Practical-LLL-Examples
title: Practical LLL Examples
---

<br>


```python
while True:
    x = randint(0, 2**100)
    y = randint(0, 2**100)
    a = randint(0, 2**500)
    b = randint(0, 2**500)
    t = a*x + b*y
    assert x*a + y*b - t == 0
    B = Matrix([
        [ a, 1, 0],
        [ b, 0, 1],
        [-t, 0, 0],
    ])
    target = vector([0, x, y])
    assert vector([x, y, 1]) * B == target
    assert target in B.LLL()
```
