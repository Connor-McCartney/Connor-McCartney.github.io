---
permalink: /cryptography/other/onelinecrypto-SeeTF-2023
title: onelinecrypto - SeeTF 2023
---

<br>
<br>

Challenge:

```python
assert __import__('re').fullmatch(r'SEE{\w{23}}',flag:=input()) and not int.from_bytes(flag.encode(),'big')%13**37
```

Other writeups:


Author's (neobeo) <https://demo.hedgedoc.org/s/DnzmwnCd7>

<https://nush.app/blog/2023/06/21/see-tf-2023/>

<https://blog.maple3142.net/2023/06/12/seetf-2023-writeups/>

```python
>>> import re
>>> for i in range(128):
...     i = chr(i)
...     if re.fullmatch(r'\w{1}', i):
...             print(i)
... 
0
1
2
3
4
5
6
7
8
9
A
B
C
D
E
F
G
H
I
J
K
L
M
N
O
P
Q
R
S
T
U
V
W
X
Y
Z
_
a
b
c
d
e
f
g
h
i
j
k
l
m
n
o
p
q
r
s
t
u
v
w
x
y
z
>>>
```

```python
>>> ord('0')
48
>>> ord('z')
122
>>> 
```

So all the flag characters are in the range 48 to 122. Not all in this range are valid but most are.


I'll start with the actual flag  `SEE{luQ5xmNUKgEEDO_c5LoJCum}` and just writing out some asserts

```python
from Crypto.Util.number import *
import re

flag = b"SEE{luQ5xmNUKgEEDO_c5LoJCum}"
assert bytes_to_long(flag) % 13**37 == 0


C = bytes_to_long(b"SEE{" + bytes(23) + b"}")

f = C
for i, c in zip(range(23, 0, -1), b"luQ5xmNUKgEEDO_c5LoJCum"):
    f += c*256**i
assert flag == long_to_bytes(f) 
```


With a kinda regular lattice attack we can find some flags with the correct length and a multiple of 13**37, but are unlucky with matching regex:


```python
from Crypto.Util.number import *

flag = b"SEE{luQ5xmNUKgEEDO_c5LoJCum}"
C = bytes_to_long(b"SEE{" + bytes(23) + b"}")
k = bytes_to_long(flag) // (13**37)

a = 85 # (ord('0') + ord('z'))/2
M = (identity_matrix(23)
    .augment(vector([0]*23))
    .augment(vector([256**i for i in range(23, 0, -1)]))
    .stack(vector([-a]*23 + [1, C]))
    .stack(vector([0]*23 + [0, -13**37]))
)
#print(M.change_ring(Zmod(10)))

# testing Matrix validity with actual flag
v = vector([c for c in b"luQ5xmNUKgEEDO_c5LoJCum"] + [1, k])
assert list(v*M) == [c-a for c in b"luQ5xmNUKgEEDO_c5LoJCum"] + [1, 0]

W = diagonal_matrix([1]*24 + [128])
for row in (M*W).LLL()/W:
    row = list(row)
    if row[-2:] == [1, 0]:
        print([i+a for i in row[:-2]])
        f = b"SEE{" + bytes([i+a for i in row[:-2]]) + b"}"
        print(bytes_to_long(f) % 13**37, f)


"""

   [. ]     [.    ]     [.    ]     [.    ]     [.    ]     [.    ]     [.    ]     [.    ]   [.  ]   [. ]   [x0-a ]
   [. ]     [.    ]     [.    ]     [.    ]     [.    ]     [.    ]     [.    ]     [.    ]   [.  ]   [. ]   [..   ]
   [1 ]     [.    ]     [.    ]     [.    ]     [.    ]     [.    ]     [.    ]     [.    ]   [.  ]   [. ]   [..   ]
   [0 ]     [1    ]     [0    ]     [0    ]     [0    ]     [0    ]     [0    ]     [0    ]   [-a ]   [0 ]   [x17-a] 
   [0 ]     [0    ]     [1    ]     [0    ]     [0    ]     [0    ]     [0    ]     [0    ]   [-a ]   [0 ]   [x18-a] 
..*[0 ]+x17*[0    ]+x18*[0    ]+x19*[1    ]+x20*[0    ]+x21*[0    ]+x22*[0    ]+x23*[0    ]+1*[-a ]+k*[0 ] = [x19-a] 
   [0 ]     [0    ]     [0    ]     [0    ]     [1    ]     [0    ]     [0    ]     [0    ]   [-a ]   [0 ]   [x20-a] 
   [0 ]     [0    ]     [0    ]     [0    ]     [0    ]     [1    ]     [0    ]     [0    ]   [-a ]   [0 ]   [x21-a]
   [0 ]     [0    ]     [0    ]     [0    ]     [0    ]     [0    ]     [1    ]     [0    ]   [-a ]   [0 ]   [x22-a] 
   [0 ]     [0    ]     [0    ]     [0    ]     [0    ]     [0    ]     [0    ]     [1    ]   [-a ]   [0 ]   [x23-a] 
   [0 ]     [0    ]     [0    ]     [0    ]     [0    ]     [0    ]     [0    ]     [0    ]   [1  ]   [0 ]   [1    ]
   [..]     [256^7]     [256^6]     [256^5]     [256^4]     [256^3]     [256^2]     [256^1]   [C  ]   [-M]   [0    ]
"""
```



With lots of lattice enumeration this basis can find the flag:

```python
from Crypto.Util.number import *
import re

def lattice_enumeration(L, bound, sol_cnt=1_000_000):
    from fpylll import IntegerMatrix, LLL
    from fpylll.fplll.gso import MatGSO
    from fpylll.fplll.enumeration import Enumeration
    A = IntegerMatrix.from_matrix(L)
    LLL.reduction(A)
    M = MatGSO(A)
    M.update_gso()
    size = int(L.nrows())
    enum = Enumeration(M, sol_cnt)
    answers = enum.enumerate(0, size, (size * bound**2), 0, pruning=None)
    for _, s in answers:
        v = IntegerMatrix.from_iterable(1, A.nrows, map(int, s))
        sv = v * A
        if abs(sv[0, size - 1]) <= bound:
            yield sv[0]


flag = b"SEE{luQ5xmNUKgEEDO_c5LoJCum}"
C = bytes_to_long(b"SEE{" + bytes(23) + b"}")
k = bytes_to_long(flag) // (13**37)

a = 85 # (ord('0') + ord('z'))/2
M = (identity_matrix(23)
    .augment(vector([0]*23))
    .augment(vector([256**i for i in range(23, 0, -1)]))
    .stack(vector([-a]*23 + [1, C]))
    .stack(vector([0]*23 + [0, -13**37]))
)

for row in lattice_enumeration(M.change_ring(ZZ), 37, sol_cnt=500_000):
    for k in [1, -1]:
        row = [k*i for i in row]
        if row[-2:] != [1, 0]:
            continue
        try:
            f = b"SEE{" + bytes([i+a for i in row[:-2]]) + b"}"
            print(bytes_to_long(f) % 13**37, f, '<--- WIN' if re.fullmatch(r'\w+', f.decode()[4:-1]) else '')
        except:
            continue
```
