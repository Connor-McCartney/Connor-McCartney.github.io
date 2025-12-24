---
permalink: /cryptography/other/PythonRandomandMersenneTwisters
title: Python Random and Mersenne Twisters
---


<br>

<br>


# how seed determines initial state

```py
from random import Random

seed = 123
rand = Random(123)
print(rand.getstate())
```

<br>

In /lib/python3.13/random.py, 

```py

    def __init__(self, x=None):
        """Initialize an instance.

        Optional argument x controls seeding, as for Random.seed().
        """

        self.seed(x)
        self.gauss_next = None

    def seed(self, a=None, version=2):
        print('here 1')
        """Initialize internal state from a seed.

        The only supported seed types are None, int, float,
        str, bytes, and bytearray.

        None or no argument seeds from current time or from an operating
        system specific randomness source if available.

        If *a* is an int, all bits are used.

        For version 2 (the default), all of the bits are used if *a* is a str,
        bytes, or bytearray.  For version 1 (provided for reproducing random
        sequences from older versions of Python), the algorithm for str and
        bytes generates a narrower range of seeds.

        """

        if version == 1 and isinstance(a, (str, bytes)):
            a = a.decode('latin-1') if isinstance(a, bytes) else a
            x = ord(a[0]) << 7 if a else 0
            for c in map(ord, a):
                x = ((1000003 * x) ^ c) & 0xFFFFFFFFFFFFFFFF
            x ^= len(a)
            a = -2 if x == -1 else x

        elif version == 2 and isinstance(a, (str, bytes, bytearray)):
            global _sha512
            if _sha512 is None:
                try:
                    # hashlib is pretty heavy to load, try lean internal
                    # module first
                    from _sha2 import sha512 as _sha512
                except ImportError:
                    # fallback to official implementation
                    from hashlib import sha512 as _sha512

            if isinstance(a, str):
                a = a.encode()
            a = int.from_bytes(a + _sha512(a).digest())

        elif not isinstance(a, (type(None), int, float, str, bytes, bytearray)):
            raise TypeError('The only supported seed types are:\n'
                            'None, int, float, str, bytes, and bytearray.')

        super().seed(a)
        self.gauss_next = None
```

Basically on init it calls self.seed(x), if it's not already an int it'll convert it to one, and then it calls out to super().seed(a)


Goto definition again took me to ~/.local/lib/python3.13/site-packages/basedpyright/dist/typeshed-fallback/stdlib/_random.pyi

But .pyi files are just Type Hint stub files, so next we want to find the c code
