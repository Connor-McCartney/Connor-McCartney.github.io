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
    [Adx, Ady, 1, 0, 0],
    [Bdx, Bdy, 0, 1, 0],
    [Cdx, Cdy, 0, 0, 1],
    [Ax + Bx + Cx - 3*centroidX, Ay + By + Cy - 3*centroidY, 0, 0, 0],
])

print(M.LLL()[0])
```

<br>

Part 2 - Circumcenter:

<br>

The distances of the circumcenter from each vertex of a triangle are equal.

$$\sqrt{(circumcenterX - x1)^2 + (circumcenterY - y1)^2} = \sqrt{(circumcenterX - x2)^2 + (circumcenterY - y2)^2} = \sqrt{(circumcenterX - x3)^2 + (circumcenterY - y3)^2}$$

<br>
<br>

$$(circumcenterX - x1)^2 + (circumcenterY - y1)^2 = (circumcenterX - x2)^2 + (circumcenterY - y2)^2$$

$$(circumcenterX - x2)^2 + (circumcenterY - y2)^2 = (circumcenterX - x3)^2 + (circumcenterY - y3)^2$$
