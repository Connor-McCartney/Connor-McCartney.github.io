---
permalink: /cryptography/other/Tan-ImaginaryCTF2023
title: Tan - ImaginaryCTF 2023
---


<br>

Challenge:

```python
print(tan(int.from_bytes(open("flag.txt", "rb").read().strip(), "big")).n(1024))
# -0.7578486465144361653056740883647981074157721568235263947812770328593706155446273431983003083023944193451634501133844062222318380912228469321984711771640337084400211818130699382144693337133198331117688092846455855532799303682791981067718891947573941091671581719597626862194794682042719495503282817868258547714
```

Solve:

<br>

$$
t = \tan(m)
$$

$$
m = \arctan(t) + k \pi
$$


Maple (author's) solution:

$$
k   \begin{bmatrix}\pi  \\ 0 \\ \pi \end{bmatrix}   
-m \begin{bmatrix}1  \\ 0 \\ 0 \end{bmatrix}  + 
1   \begin{bmatrix}at  \\ 1 \\ at \end{bmatrix}  
=   \begin{bmatrix}0  \\ 1  \\ m \end{bmatrix}
$$

```python
bits = 1024
t = -0.7578486465144361653056740883647981074157721568235263947812770328593706155446273431983003083023944193451634501133844062222318380912228469321984711771640337084400211818130699382144693337133198331117688092846455855532799303682791981067718891947573941091671581719597626862194794682042719495503282817868258547714
at = arctan(t)
pi = pi.n(bits)

M = Matrix(QQ, [
    [pi, 0, pi],
    [1,  0,  0],
    [at, 1, at],
])

W = diagonal_matrix([2**bits, 1, 1])
M = (M*W).LLL()/W
_, _, m = M[0] # target (0, 1, m)
print(bytes.fromhex(f'{int(m):x}'))
```

<br>

<br>

Alternative:

$$
k   \begin{bmatrix}\pi  \\ 0 \\ 0 \end{bmatrix}  + 
m \begin{bmatrix}-1  \\ 0 \\ 1 \end{bmatrix}  + 
1   \begin{bmatrix}at  \\ 1 \\ 0 \end{bmatrix}  
=   \begin{bmatrix}0  \\ 1  \\ m \end{bmatrix}
$$

```python
bits = 1024
t = -0.7578486465144361653056740883647981074157721568235263947812770328593706155446273431983003083023944193451634501133844062222318380912228469321984711771640337084400211818130699382144693337133198331117688092846455855532799303682791981067718891947573941091671581719597626862194794682042719495503282817868258547714
at = arctan(t)
pi = pi.n(bits)

M = Matrix(QQ, [
    [pi, 0, pi],
    [1,  0,  0],
    [at, 1, at],
])

W = diagonal_matrix([2**bits, 1, 1])
M = (M*W).LLL()/W
_, _, m = M[0] # target (0, 1, m)
print(bytes.fromhex(f'{int(m):x}'))
```