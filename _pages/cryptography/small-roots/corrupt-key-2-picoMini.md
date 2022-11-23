---
permalink: /cryptography/small-roots/corrupt-key-2-picoMini
title: corrupt-key-2 picoMini
---

<br>


We are given p with 3 chunks missing:

```
p = 0xfe8984407b0816cc28e5ccc6bb7379??????????ca3806dd2cfdfc8d616b????????6109a4dbe3876b8d1b8adc9175dfba0e1ef318801648d6??????????a05b
```

I used this multivariate Coppersmith implementation: <https://gist.github.com/chrsow/f766786bfcb0034d8c6c9372b822222c> <br>

```py
class IIter:
    def __init__(self, m, n):
        self.m = m
        self.n = n
        self.arr = [0 for _ in range(n)]
        self.sum = 0
        self.stop = False
    
    def __iter__(self):
        return self

    def __next__(self):
        if self.stop:
            raise StopIteration
        ret = tuple(self.arr)
        self.stop = True
        for i in range(self.n - 1, -1, -1):
            if self.sum == self.m or self.arr[i] == self.m:
                self.sum -= self.arr[i]
                self.arr[i] = 0
                continue
            
            self.arr[i] += 1
            self.sum += 1
            self.stop = False
            break
        return ret

def coppersmith(f, bounds, m=1, t=1):
    n = f.nvariables()
    N = f.base_ring().cardinality()
    f /= f.coefficients().pop(0) #monic
    f = f.change_ring(ZZ)
    x = f.parent().objgens()[1] 

    g = []
    monomials = []
    Xmul = []
    for ii in IIter(m, n):
        k = ii[0]
        g_tmp = f^k * N^max(t-k, 0)
        monomial = x[0]^k
        Xmul_tmp = bounds[0]^k
        for j in range(1, n):
            g_tmp *= x[j]^ii[j]
            monomial *= x[j]^ii[j]
            Xmul_tmp *= bounds[j]^ii[j]
        g.append(g_tmp)
        monomials.append(monomial)
        Xmul.append(Xmul_tmp)

    B = Matrix(ZZ, len(g), len(g))
    for i in range(B.nrows()):
        for j in range(i + 1):
            if j == 0:
                B[i,j] = g[i].constant_coefficient()
            else:
                v = g[i].monomial_coefficient(monomials[j])
                B[i,j] = v * Xmul[j]

    print("LLL...")
    B = B.LLL()
    print("LLL finished")

    ###############################################

    print("polynomial reconstruction...")

    h = []
    for i in range(B.nrows()):
        h_tmp = 0
        for j in range(B.ncols()):
            if j == 0:
                h_tmp += B[i, j]
            else:
                assert B[i,j] % Xmul[j] == 0
                v = ZZ(B[i,j] // Xmul[j])
                h_tmp += v * monomials[j]
        h.append(h_tmp)

    x_ = [ var(f'x{i}') for i in range(n) ]
    for ii in Combinations(range(len(h)), k=n):
        f = symbolic_expression([ h[i](x) for i in ii ]).function(x_)
        jac = jacobian(f, x_)
        v = vector([ t // 2 for t in bounds ])
        for _ in range(100): #1000
            kwargs = {f'x{i}': v[i] for i in range(n)}
            tmp = v - jac(**kwargs).inverse() * f(**kwargs)
            v = vector(float(d) for d in tmp)
        v = [ int(_.round()) for _ in v ]
        if h[0](v) == 0:
            return v

    return []


N = 0xc20d4f0792f162e3f3486f47c2c5b05696ba5c81ec09f5386bf741b7289b85e2d744559825a23b0ae094da214f3158344e5d5ba86fb1ecd1f40c8682a7bee55021eba772e23793001a38b9cccbfdc1d9316cccc3b79acd045c512b44e0f3697383958113a280791e17c23fe80fa38099e4907f70f4d228285aac69ed2d3bcf99
_p = 0xfe8984407b0816cc28e5ccc6bb73790000000000ca3806dd2cfdfc8d616b000000006109a4dbe3876b8d1b8adc9175dfba0e1ef318801648d60000000000a05b

PR.<x0,x1,x2> = PolynomialRing(Zmod(N), 3)
f = _p + 2**16*x0 + 2**240*x1 + 2**352*x2
x0, x1, x2 = coppersmith(f, bounds=(2**40,2**32,2**40,), m=6)
p = int(f(x0,x1,x2))

q = N//p
e = 65537
d = int(pow(e, -1, (p-1)*(q-1)))
c = open('msg.enc', 'rb').read()
c = int(bytes.hex(c), 16)
m = int(pow(c, d, N))
print(bytes.fromhex(hex(m)[69:]).decode())
```

<br>

Extra:

A function to create the poynomial from ?s in a string:

```python
_p = "fe8984407b0816cc28e5ccc6bb7379??????????ca3806dd2cfdfc8d616b????????6109a4dbe3876b8d1b8adc9175dfba0e1ef318801648d6??????????a05b"

c = 0
l = []
b = 0
bounds = []
for i, h in enumerate(_p.split("?")[::-1]):
    if h != '':
        bounds.append(2**b)
        b = 4
        c += len(h)*4
        l.append(c)
    else:
        b += 4
    c += 4
l = l[:-1]
bounds = bounds[1:]
xs = [f"x{i}" for i in range(len(l))]
PR = PolynomialRing(Zmod(N), len(l), xs)
f = int(_p.replace("?", "0"), 16) + sum([2**i * PR.objgens()[1][n] for n, (i, x) in enumerate(zip(l, xs))])

roots = coppersmith(f, bounds, m=6)
print(roots)
```
