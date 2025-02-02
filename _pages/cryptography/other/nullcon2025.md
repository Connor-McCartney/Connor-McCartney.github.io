---
permalink: /cryptography/other/nullcon2025
title: nullcon HackIM CTF Goa 2025
---

<br>

<br>

[Challenge Files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2025/nullcon)

<br>

<br>


# registration

<br>

n, a, e are given. 

```python
	def verify(self, msg, s):
		if type(msg) == str: msg = msg.encode()
		h = number.bytes_to_long(sha256(msg).digest())
		return pow(s,self.e,self.n) == pow(self.a, h, self.n)
```

Given some H, to verify, we must solve for a valid S, such that:

$$S^e \equiv a^H \pmod n$$

Rearrange for S:

$$S \equiv (a^H)^d \equiv a^{d \cdot H} \pmod n$$

<br>

We can also collect as many signatures as we want. 

```python
	def sign(self, msg):
		if type(msg) == str: msg = msg.encode()
		h = number.bytes_to_long(sha256(msg).digest())
		return pow(self.a, h * self.d, self.n)
```

We receive some si and hi, where:

$$s_i \equiv a^{h_i \cdot d} \pmod n$$

<br>

Now let's introduce some new unknowns xi. 

Suppose we construct S as 

$$S \equiv {s_0}^{x_0} \cdot {s_1}^{x_1} \cdot {s_2}^{x_2} \cdot ... \pmod n$$

Now we just want to solve for these xi. 

Substitute in our previous expressions for S and si:

$$ a^{d \cdot H} \equiv a^{d \cdot x_0 \cdot h_0} \cdot a^{d \cdot x_1 \cdot h_1} \cdot a^{d \cdot x_2 \cdot h_2} \cdot ... \pmod n$$

$$ a^{d \cdot H} \equiv a^{d \cdot (x_0 \cdot h_0 + x_1 \cdot h_1 + x_2 \cdot h_2 + ...)} \pmod n$$

$$ H = x_0 \cdot h_0 + x_1 \cdot h_1 + x_2 \cdot h_2 + ... $$

And we can try solve this with LLL. 

<br>

Solve script:






<br>

<br>

# coinflip

If we just keep betting 1 amount then we can collect many outputs and use that to determine some states. 

then if we can just solve a and m, we can predict future states. 

```python
            self.state = self.a * pow(self.state, 3, self.m) % self.m
```

$$s_{i+1} = a \cdot s_i^3 \pmod m$$


We can try eliminate a and then get m with gcd like so

```python
from Crypto.Util.number import *

n = 64
m = getRandomNBitInteger(n)
print(f'{m = }')

while True:
    a = bytes_to_long(os.urandom(n >> 3)) % m # n/8 bytes
    if gcd(a, m) == 1: break
while True:
    s0 = bytes_to_long(os.urandom(n >> 3)) % m # n/8 bytes
    if gcd(s0, m) == 1: break

s1 = a * pow(s0, 3, m) % m
s2 = a * pow(s1, 3, m) % m
s3 = a * pow(s2, 3, m) % m
...

assert s1 * pow(s0, -3, m) % m == a % m
assert s2 * pow(s1, -3, m) % m == a % m
assert s3 * pow(s2, -3, m) % m == a % m
...


assert ((s1 * s1**3) - (s2 * s0**3)) % m == 0
assert ((s2 * s2**3) - (s3 * s1**3)) % m == 0

mm = gcd((s1 * s1**3) - (s2 * s0**3), (s2 * s2**3) - (s3 * s1**3))
print(f'{mm = }')
```

<br>

Final solve script:









<br> <br> <br> <br>
