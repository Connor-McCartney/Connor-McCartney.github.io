---
permalink: /cryptography/rsa/PrimeRotation-CompfestCTF-16-2024
title:  Prime Rotation - Compfest CTF 16 2024
---

<br>

<br>

Challenge:

```python
from sage.all import *
from Crypto.Util.number import *

flag = b'COMPFEST16{REDACTED}'

while True:
    p = next_prime(randrange(10*299, 10**300))
    if len(str(p)) != 300:
        continue
    q = Integer(int(str(p)[200:] + str(p)[100:200] + str(p)[:100]))
    if is_prime(q):
        if len(str(p*q)) == 600:
            n = p*q
            ct = pow(bytes_to_long(flag), 65537, n)
            print("ct =", ct)
            print("n =", n)
            break
```

```
ct = 112069250204847858434951864919494772437772309551100894283802890969294921153695033680308824238138045767163824928036225288640262479846659348456350274690146950091938837191909645393428229485475109811982995836390466223992421552045075462248484268261988513215970281479307051354279950516448154191270415379751945199844597328599643336925042296451667124633421375106611252124455800238151031224064949216810203270294287136489525063218922502754179790238733845401863560349247348618842377798382953621069669066126553437295321747661018783680078904246779293823424410074601480963728455972270367310938167374435974788290895
n = 338157083965246057571026756360795557480615383698977322739773119119768631064965448629444858368455612367321181172346297206715981930133542614118983474663804909611201532833645460572467511167118907653891577684641980804552415671777685960512779105153093618092748148197835625397758340520102160357258334250293520469968267915267730466529829639830017519012622973967936476883318368260247264026111745427467952456821708517718723537977525795647439220142795157435101213559895031087961640507169858237537062387315301224943694997736792045576174622866155698202883578606065005204942324227724078229357430907077534468953279
```

<br>

<br>


Solve:

Reading the code, we can see that the top and bottom third digits of p and q are swapped. 

Split p and q into thirds, I'll use 3 variables a,b,c:

$$
p = a \cdot 10^{200} + b \cdot 10^{100} + c
$$

$$
q = c \cdot 10^{200} + b \cdot 10^{100} + a
$$

$$
n = p \cdot q = (a \cdot 10^{200} + b \cdot 10^{100} + c) (c \cdot 10^{200} + b \cdot 10^{100} + a)
$$

If you are lazy to expand by hand use sage:

```python
sage: var('a b c ten')
(a, b, c, ten)
sage: ((a*ten^200 + b*ten^100 + c) * (c*ten^200 + b*ten^100 + a)).expand()
a*c*ten^400 + a*b*ten^300 + b*c*ten^300 + a^2*ten^200 + b^2*ten^200 + c^2*ten^200 + a*b*ten^100 + b*c*ten^100 + a*c
```

Now factor out powers of 10:

$$
n = (a \cdot c) \cdot 10^{400} + (a \cdot b + b \cdot c) \cdot 10^{300} + (a^2 + b^2 + c^2) \cdot 10^{200} + (a \cdot b + b \cdot c) \cdot 10^{100} + a \cdot c
$$

Let

$$
X = a \cdot c
$$

$$
Y = a \cdot b + b \cdot c
$$

$$
Z = a^2 + b^2 + c^2
$$

Thus, 

$$
n = X \cdot 10^{400} + Y \cdot 10^{300} + Z \cdot 10^{200} + Y \cdot 10^{100} + X
$$

$$
n = X \cdot (10^{400} + 1) + Y \cdot (10^{300} + 10^{100}) + Z \cdot 10^{200}
$$

We can solve for X,Y,Z with LLL, I used [Blupper's repo for convenience](https://github.com/TheBlupper/linineq). 

Then, we have 3 equations with 3 unknowns so we can solve a,b,c directly. 

For this I just used sage's `solve` function with the sympy option. 

Since we have to enumerate multiple solutions for X,Y,Z, when the wrong X,Y,Z is used to try solve a,b,c, 

the sympy solver will just hang because there is no solution. So, I just added a simple alarm. 
