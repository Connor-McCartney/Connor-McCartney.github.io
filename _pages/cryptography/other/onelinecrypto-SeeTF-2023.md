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
