---
permalink: /cryptography/other/Geometry-Hash-Balsn-CTF-2023
title: Geometry Hash - Balsn CTF 2023
---

<br>

Challenge:

```python
import secrets
from sympy import N, Float, Point, Triangle

#from secret import FLAG
FLAG = "testflag"

PRECISION = 1337

def main():
	import signal
	signal.alarm(20)

	levels = [
		lambda x: x.centroid,
		lambda x: x.circumcenter,
		lambda x: x.incenter,
	]
	try:
		for level in levels:
			challenge(level)
		print(FLAG)
	except:
		print("Wasted")

def challenge(hash_function):
	# raise an error if the user fails the challenge

	print("===== Challenge =====")
	A = RandomLine()
	B = RandomLine()
	C = RandomLine()

	# print parameters
	A.print()
	B.print()
	C.print()

	i, j, k = [secrets.randbits(32) for _ in range(3)]
	triangle = Triangle(A[i], B[j], C[k])
	hsh = hash_function(triangle)
	
	print(Float(hsh.x, PRECISION))
	print(Float(hsh.y, PRECISION))

	_i, _j, _k = map(int, input("> ").split(" "))
	assert (i, j, k) == (_i, _j, _k)
	print("Mission passed")

class RandomLine:
	def __init__(self):
		self.x = randFloat()
		self.y = randFloat()
		self.dx = randFloat()
		self.dy = randFloat()

	def __getitem__(self, i):
		return Point(self.x + self.dx * i, self.y + self.dy * i, evaluate=False)

	def print(self):
		print(self.x)
		print(self.y)
		print(self.dx)
		print(self.dy)

def randFloat():
	# return a random float between -1 and 1
	return -1 + 2 * Float(secrets.randbits(PRECISION), PRECISION) / (1 << PRECISION)

if __name__ == "__main__":
	main()
```

<br>

Solve:

<br>

```python
	A = RandomLine()
	B = RandomLine()
	C = RandomLine()
	i, j, k = [secrets.randbits(32) for _ in range(3)]
	triangle = Triangle(A[i], B[j], C[k])
```

<br>

Note that the vertices of the triangles are unknown, given by: <br>

```python
	def __getitem__(self, i):
		return Point(self.x + self.dx * i, self.y + self.dy * i, evaluate=False)
```

<br>

So I'll denote:

$$ (x1, \ y1) = (Ax + Adx \cdot i, \ Ay + Ady \cdot i) $$

$$ (x2, \ y2) = (Bx + Bdx \cdot j, \ By + Bdy \cdot j) $$

$$ (x3, \ y3) = (Cx + Cdx \cdot k, \ Cy + Cdy \cdot k) $$


<br>

Part 1 - Centroid:

We have 2 equations with 3 relatively small unknowns (i, j, k):

$$\text{centroidX} = \frac{x1 + x2 + x3}{3} = \frac{Ax + Adx \cdot i + Bx + Bdx \cdot j + Cx + Cdx \cdot k}{3}$$

$$\text{centroidY} = \frac{y1 + y2 + y3}{3} = \frac{Ay + Ady \cdot i + By + Bdy \cdot j + Cy + Cdy \cdot y}{3}$$

<br>

Now we can rewrite them for LLL:

$$i \begin{bmatrix}Adx \\ Ady \\ 1 \\ 0 \\ 0\end{bmatrix} + j \begin{bmatrix}Bdx \\ Bdy \\ 0 \\ 1 \\ 0\end{bmatrix} + k \begin{bmatrix}Cdx \\ Cdy \\ 0 \\ 0 \\ 1\end{bmatrix} + \begin{bmatrix}Ax+Bx+Cx-3\cdot\text{centroidX} \\ Ay+By+Cy-3\cdot\text{centroidY} \\ 0 \\ 0 \\ 0\end{bmatrix} = \begin{bmatrix}0 (\pm \text{precision error}) \\ 0 (\pm \text{precision error}) \\ i \\ j \\ k\end{bmatrix}$$

<br>

Demo:

```python
def r():
    return randint(0, 2**1000)

Ax, Bx, Cx    = r(), r(), r()
Ay, By, Cy    = r(), r(), r()
Adx, Bdx, Cdx = r(), r(), r()
Ady, Bdy, Cdy = r(), r(), r()

i, j, k = [randint(0, 2**32) for _ in range(3)]
print(i, j, k)
centroidX = (Adx*i + Bdx*j + Cdx*k + Ax + Bx + Cx) // 3
centroidY = (Ady*i + Bdy*j + Cdy*k + Ay + By + Cy) // 3

M = Matrix([
    [                       Adx,                        Ady, 1, 0, 0],
    [                       Bdx,                        Bdy, 0, 1, 0],
    [                       Cdx,                        Cdy, 0, 0, 1],
    [Ax + Bx + Cx - 3*centroidX, Ay + By + Cy - 3*centroidY, 0, 0, 0],
])

print(M.LLL()[0])
```

<br>

Part 2 - Circumcenter:

<br>

The distances of the circumcenter (ccX, ccY) from each vertex ((x1, y1), (x2, y2), (x3, y3)) of a triangle are equal.

$$\sqrt{(ccX - x1)^2 + (ccY - y1)^2} = \sqrt{(ccX - x2)^2 + (ccY - y2)^2} = \sqrt{(ccX - x3)^2 + (ccY - y3)^2}$$

<br>
We can make two equations:
<br>

$$0 = (ccX - x1)^2 + (ccY - y1)^2 - (ccX - x2)^2 - (ccY - y2)^2$$

$$0 = (ccX - x1)^2 + (ccY - y1)^2 - (ccX - x3)^2 - (ccY - y3)^2$$

<br>
Adding them:
<br>

$$0 = 2(ccX - x1)^2 + 2(ccY - y1)^2 - (ccX - x2)^2 - (ccY - y2)^2 - (ccX - x3)^2 - (ccY - y3)^2$$


<br>


$$0 = 2(ccX - (Ax + Adx \cdot i))^2 + 2(ccY - (Ay + Ady \cdot i))^2$$

$$- (ccX - (Bx + Bdx \cdot j))^2 - (ccY - (By + Bdy \cdot j))^2$$

$$- (ccX - (Cx + Cdx \cdot k))^2 - (ccY - (Cy + Cdy \cdot k))^2$$


<br>


$$0 = 2 \cdot {ccX}^2 - 4 \cdot ccX \cdot Ax - 4 \cdot ccX \cdot Adx \cdot i + 2\cdot {Ax}^2 + 4 \cdot Ax \cdot Adx \cdot i + 2{(Adx)}^2 i^2$$ 

$$  + 2 \cdot {ccY}^2 - 4 \cdot ccY \cdot Ay - 4 \cdot ccY \cdot Ady \cdot i + 2 \cdot {Ay}^2 + 4 \cdot Ay \cdot Ady \cdot i + 2{(Ady)}^2 i^2$$

$$- \ {ccX}^2 + 2 \cdot ccX \cdot Bx + 2 \cdot ccX \cdot Bdx \cdot j - {Bx}^2 - 2 \cdot Bx \cdot Bdx \cdot j - {(Bdx)}^2 j^2$$

$$- \ {ccY}^2 + 2 \cdot ccY \cdot By + 2 \cdot ccY \cdot Bdy \cdot j - {By}^2 - 2 \cdot By \cdot Bdy \cdot j - {(Bdy)}^2 j^2$$

$$- \ {ccX}^2 + 2 \cdot ccX \cdot Cx + 2 \cdot ccX \cdot Cdx \cdot k - {Cx}^2 - 2 \cdot Cx \cdot Cdx \cdot k - {(Cdx)}^2 k^2$$

$$- \ {ccY}^2 + 2 \cdot ccY \cdot Cy + 2 \cdot ccY \cdot Cdy \cdot k - {Cy}^2 - 2 \cdot Cy \cdot Cdy \cdot k - {(Cdy)}^2 k^2$$

<br>

$$0 = i^2 \cdot (2{(Adx)}^2 + 2{(Ady)}^2) + j^2 \cdot (-{(Bdx)}^2 - {(Bdy)}^2) + k^2 \cdot (-{(Cdx)}^2 - {(Cdy)}^2)$$

$$+ ...$$
