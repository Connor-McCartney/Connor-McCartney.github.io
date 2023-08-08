<https://github.com/orisano/olll/blob/master/olll.py>

```py
class Vector(list):
    def sdot(self):
        return self.dot(self)

    def dot(self, rhs):
        return sum(map(lambda x: x[0] * x[1], zip(self, Vector(rhs))))

    def proj_coff(self, rhs):
        return self.dot(Vector(rhs)) / self.sdot()

    def proj(self, rhs):
        return self.mul(self.proj_coff(Vector(rhs)))

    def subtract(self, rhs):
        return Vector(x - y for x, y in zip(self, Vector(rhs)))

    def mul(self, a):
        return Vector(x * a for x in self)


def gramschmidt(v):
    u = []
    for vi in v:
        ui = Vector(vi)
        for uj in u:
            ui = ui.subtract(uj.proj(vi))
        if any(ui):
            u.append(ui)
    return u


def LLL(basis, delta=0.99):
    """
    >>> reduction([[1, 1, 1], [-1, 0, 2], [3, 5, 6]])
    [[0, 1, 0], [1, 0, 1], [-1, 0, 2]]
    """
    n = len(basis)
    basis = list(map(Vector, basis))
    ortho = gramschmidt(basis)

    def mu(i: int, j: int):
        return ortho[j].proj_coff(basis[i])

    k = 1
    while k < n:
        for j in range(k - 1, -1, -1):
            mu_kj = mu(k, j)
            if abs(mu_kj) > 0.5:
                basis[k] = basis[k].subtract(basis[j].mul(round(mu_kj)))
                ortho = gramschmidt(basis)

        if ortho[k].sdot() >= (delta - mu(k, k - 1)**2) * ortho[k - 1].sdot():
            k += 1
        else:
            basis[k], basis[k - 1] = basis[k - 1], basis[k]
            ortho = gramschmidt(basis)
            k = max(k - 1, 1)

    return [list(map(int, b)) for b in basis]


print(  LLL([[1, 1, 1], [-1, 0, 2], [3, 5, 6]], 0.99)  )
```
