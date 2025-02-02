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

$$S \equiv (a^H)^d \equiv a^d \cdot a^H \pmod n$$

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

Now let's introduce some new unknowns yi. 

Suppose we construct S as 

$$S \equiv {s_0}^{y_0} + {s_1}^{y_1} + {s_2}^{y_2} + ... \pmod n$$

Now we just want to solve for these yi. 

Substitute in our previous expressions for S and si:

$$ a^d \cdot a^H \equiv a^d \cdot \left( a^{y_0 \cdot h_0} + a^{y_1 \cdot h_1} + a^{y_2 \cdot h_2} + ... \right) \pmod n$$
