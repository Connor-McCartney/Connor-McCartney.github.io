---
permalink: /cryptography/other/Finding-a-subset-of-bytes-that-XOR-to-some-target
title: Finding a subset of bytes that XOR to some target
---


<br>

```python
from os import urandom
from Crypto.Util.number import bytes_to_long
from Crypto.Util.strxor import strxor
from functools import reduce

def bytes_to_binary(b):
    return [int(i) for i in f"{bytes_to_long(b):064b}"]

def solve(random_bytes, target):
    vecs = [bytes_to_binary(b) for b in random_bytes]
    M = Matrix(GF(2), vecs).transpose()
    if M.rank() != len(random_bytes):
        print("all vectors not linearly independent")
        return []
    solve = M.solve_right(vector(bytes_to_binary(target)))

    ret = []
    for s, v in zip(solve, random_bytes):
        if s == 1:
            ret.append(v)
    return ret

def main():
    while True:
        try:
            random_bytes = [urandom(8) for _ in range(64)]
            target = urandom(8)
            solution = solve(random_bytes, target)
            print(reduce(strxor, solution) == target)
            return
        except:
            continue

main()
```
