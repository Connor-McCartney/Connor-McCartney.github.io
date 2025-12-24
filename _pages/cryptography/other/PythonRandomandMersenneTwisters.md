---
permalink: /cryptography/other/PythonRandomandMersenneTwisters
title: Python Random and Mersenne Twisters
---


<br>

<br>


# how seed determines initial state

```py
from random import Random

seed = 123
rand = Random(123)
print(rand.getstate())
```

