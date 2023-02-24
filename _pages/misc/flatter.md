

A look at <https://github.com/keeganryan/flatter>

@Neobeo shared a quick sage wrapper:

```python
from subprocess import check_output
from re import findall
def flatter(M):
    # compile https://github.com/keeganryan/flatter and put it in $PATH
    z = '[[' + ']\n['.join(' '.join(map(str,row)) for row in M) + ']]'
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int,findall(b'-?\\d+', ret)))
```
