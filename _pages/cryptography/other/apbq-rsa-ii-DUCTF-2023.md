---
permalink: /cryptography/other/apbq-rsa-ii-DUCTF-2023
title: apbq-rsa-ii - DUCTF 2023
---

<br>
<br>

[Challenge Files](https://github.com/DownUnderCTF/Challenges_2023_Public/tree/main/crypto/apbq-rsa-ii)

```python
from Crypto.Util.number import getPrime, bytes_to_long
from random import randint

p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 0x10001

hints = []
for _ in range(3):
    a, b = randint(0, 2**312), randint(0, 2**312)
    hints.append(a * p + b * q)

FLAG = open('flag.txt', 'rb').read().strip()
c = pow(bytes_to_long(FLAG), e, n)
print(f'{n = }')
print(f'{c = }')
print(f'{hints = }')
```

<br>

Solve:

We have 3 equations:

$$h_1 = a_1 \ p + b_1 \ q$$

$$h_2 = a_2 \ p + b_2 \ q$$

$$h_3 = a_3 \ p + b_3 \ q$$

Now let's let:

$$x_1 = a_1 \ p, \ \ \ \ x_2 = a_2 \ p, \ \ \ \ x_3 = a_3 \ p$$

We can get 3 new equations:

$$h_2 \ x_1 - h_1 \ x_2 = 0 \text{ (mod n)}$$

$$h_3 \ x_1 - h_1 \ x_3 = 0 \text{ (mod n)}$$

$$h_3 \ x_2 - h_2 \ x_3 = 0 \text{ (mod n)}$$

Which we can solve with a lattice:

$$x_1 \begin{bmatrix}h2  \\ h3  \\ 0 \\ 1 \\ 0 \\ 0\end{bmatrix} + x_2 \begin{bmatrix}-h1  \\ 0  \\ h3 \\ 0 \\ 1 \\ 0\end{bmatrix} + x_3 \begin{bmatrix}0  \\ -h1  \\ -h2 \\ 0 \\ 0 \\ 1\end{bmatrix} + k_1 \begin{bmatrix}n  \\ 0  \\ 0 \\ 0 \\ 0 \\ 0\end{bmatrix} + k_2 \begin{bmatrix}0  \\ n  \\ 0 \\ 0 \\ 0 \\ 0\end{bmatrix} + k_3 \begin{bmatrix}0  \\ 0  \\ n \\ 0 \\ 0 \\ 0\end{bmatrix} =  \begin{bmatrix}0  \\ 0  \\ 0 \\ x_1 \\ x_2 \\ x_3\end{bmatrix}$$

<br>

```python
from Crypto.Util.number import long_to_bytes

e = 0x10001
n = 19604411241131769363446674414275822275458180476470552084588074159518829172495704100505151090666577360738167275118902368371310303168115405693118232835691333564186301532462296609038929723894816307213749698854885742811071911120730847279568876996811433319487396434622751326281226335521193361938724747445445693062336009352580319440819629260614301234971135026395941954109172567154559773437059174108362692061503832044135079892892132874437669744266153424229215832487832220575345912010076934611701182205068942016022731469408259665250938484104489962832891496953003599692437819685070043991828977623632396604764153766442526750861
c = 16285668872352205553535195410427806596787838055817589230402081772267074935944610262823936480340920868690431897597533868262062616060037808676539290467732178272289192993251540763800683055555842878669862850848141950704501553807462214356142018528608581546359772903806691435935873069006470208826518183488708349814610769150918356795466688732617809664831695402633481224388822180989614886783145141129157248734213457746877012517003702540070132542733288350979858743766340483503277308585752213220454288897741262154622769402029906981612699288206404870733274360554941455758083078106150045394190625280336371690998959720015636304971
h1, h2, h3 = [773921762798470573303163880380136299117907456177270598418425239064611119645412840945432294881005107606154919094297188183879147500755682510817840590276985061404198538395146658442221987303866921786284298394947485319583779671756246394491275898343836522004269864718405399287554020900395899143149709408762450693357109188640512875099087677956684946219071353228860650842182953922400081939934842271539450654323, 1506346165967409413422972644306025635334450240732478358292064973873339506571546529986180145578525288707094235933775031106971678278204568310035260899591267480098015553318079460357474533531922997212816264042117005473870580122983241038123126855791876827449194400045937398578284016176289760858365282167537689282643483235235028505475719615108102516557986483184881658418430287064598580231630440534438966422546, 531028473288853560172466570664059891687387973059926255729701774553291285115938502989142318123512885100092638435578692032744904444237266108167428726130739434630511943317357743527053899234918340191006102436386051432760331852295930159729030763033361158582919982579082557775409422474301977588011705535991555292564664521116375190464371518812625647175447427886432255779925378071998411170643507118426289778768]

M = Matrix([
    [h2 , h3 , 0  , 1, 0, 0],
    [-h1, 0  , h3 , 0, 1, 0],
    [0  , -h1, -h2, 0, 0, 1],
    [n  , 0  , 0  , 0, 0, 0],
    [0  , n  , 0  , 0, 0, 0],
    [0  , 0  , n  , 0, 0, 0],
])

k = 2**(1024 + 312)
W = diagonal_matrix([k, k, k, 1, 1, 1])
M = (M*W).LLL() / W
for row in M:
    if row[:3] != 0:
        continue
    _, _, _, x1, x2, x3 = row
    for x in (x1, x2, x3):
        p = gcd(x,n)
        if p == 1:
            continue
        q = n//p
        d = pow(e, -1, (p-1)*(q-1))
        print(long_to_bytes(int(pow(c, d, n))))
```

<br>


--- 

Extension: 

Can you do it with just 2 hints?!

Yes!

Let:

$$x_1 = a_2 \cdot b_2$$

$$x_2 = a_1 \cdot b_1$$

$$x_3 = -a_1 \cdot b_2 - a_2 \cdot b_1$$

Consider:

$$x_1 \cdot h_1 \cdot h_1 + x_2 \cdot h_2 \cdot h_2 + x_3 \cdot h_1 \cdot h_2$$

It equals 0 mod n, and using LLL you can get some divisor of x1 x2 and x3:

```python
while True:
    p = random_prime(2**1024)
    q = random_prime(2**1024)
    n = p * q

    a1, a2, b1, b2 = [randint(0, 2**312) for _ in range(4)]
    h1 = a1 * p + b1 * q
    h2 = a2 * p + b2 * q

    x1 = a2*b2
    x2 = a1*b1
    x3 = -a1*b2 - a2*b1
    assert 0 == (x1*h1*h1 + x2*h2*h2 + x3*h1*h2) % n

    M = Matrix([
        [1, 0, 0, h1 * h1],
        [0, 1, 0, h2 * h2],
        [0, 0, 1, h1 * h2],
        [0, 0, 0, n]
    ])

    # target: [x1, x2, x3, 0]
    W = diagonal_matrix([1, 1, 1, 2**(312 * 2)])
    M = (M*W).LLL()/W
    X1, X2, X3, _ = M[0]
    print(x1//X1, x2//X2, x3//X3)
```

<br>

Remember 

$$x_1 \cdot h_1 \cdot h_1 + x_2 \cdot h_2 \cdot h_2 + x_3 \cdot h_1 \cdot h_2 \equiv 0 \pmod n$$

It must be 

$$x_1 \cdot h_1 \cdot h_1 + x_2 \cdot h_2 \cdot h_2 + x_3 \cdot h_1 \cdot h_2 + k \cdot n = 0$$

for some k. We can easily solve this since it's the only unknown:

```python
k = -(x1*h1*h1 + x2*h2*h2 + x3*h1*h2)//n
assert 0 == (x1*h1*h1 + x2*h2*h2 + x3*h1*h2) + k*n
```

Now what is k actually equal to in terms of our variables? 

We can expand our equation...

```python
var('p q a1 a2 b1 b2 k')
n = p * q
h1 = a1 * p + b1 * q
h2 = a2 * p + b2 * q

x1 = a2*b2
x2 = a1*b1
x3 = -a1*b2 - a2*b1
f = x1*h1*h1 + x2*h2*h2 + x3*h1*h2 + k*n
print(f.expand())
print((f/n).expand())
```

```python
-a2^2*b1^2*p*q + 2*a1*a2*b1*b2*p*q - a1^2*b2^2*p*q + k*p*q
-a2^2*b1^2 + 2*a1*a2*b1*b2 - a1^2*b2^2 + k
```

So we have

```python
assert k == a2^2*b1^2 - 2*a1*a2*b1*b2 + a1^2*b2^2
```

Factor it:

```python
x4 = a2*b1
x5 = a1*b2
assert k == (x4 - x5)^2
assert isqrt(k) == x4-x5 or isqrt(k) == x5-x4
```

We want to solve x5 and x4. We've already solved x3 so we can use that to help us do that:

```python
assert x3 == -x5 - x4
assert x4 == -x5 - x3
assert x5 == (isqrt(k)-x3)//2 or x5 == (-isqrt(k)-x3)//2
```

Finally we can take GCD and divide by some small factor :)


```python
def solve(h1, h2, n):
    M = Matrix([
        [1, 0, 0, h1 * h1],
        [0, 1, 0, h2 * h2],
        [0, 0, 1, h1 * h2],
        [0, 0, 0, n]
    ])
    W = diagonal_matrix([1, 1, 1, 2**(312 * 2)])
    M = (M*W).LLL()/W
    row = M[0]
    if row[0] < 0:
        row *= -1
    for i in range(1, 1000):
        x1, x2, x3, _ = row*i
    
        k = -(x1*h1*h1 + x2*h2*h2 + x3*h1*h2)//n
        for x5 in [(isqrt(k)-x3)//2, (-isqrt(k)-x3)//2]:
            x4 = -x5 - x3
            for j in range(1, 1000):
                a1 = gcd(x2, x5)//j
                a2 = gcd(x1, x4)//j
                b1 = x4 // a2
                b2 = x5 // a1
                p = int((a1 * h2 - a2 * h1) // isqrt(k))
                if n%p == 0:
                    return p, n//p

    return 0, 0

def main():
    p = random_prime(2**1024)
    q = random_prime(2**1024)
    a1, a2, b1, b2 = [randint(0, 2**312) for _ in range(4)]

    n = p * q
    h1 = a1 * p + b1 * q
    h2 = a2 * p + b2 * q

    p, q = solve(h1, h2, n)
    print(f'{p = }\n{q = }\n')
    print(p*q == n)

while True:
    main()
```
