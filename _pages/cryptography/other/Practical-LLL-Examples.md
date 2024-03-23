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
        [1, 0,  a],
        [0, 1,  b],
        [0, 0, -t],
    ])
    target = vector([x, y, 0])
    assert vector([x, y, 1]) * B == target
    assert target in B.LLL()
```
