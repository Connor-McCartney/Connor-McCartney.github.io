---
permalink: /cryptography/other/last-digit-DUCTF-2022
title: last-digit DUCTF-2022
---

<br>
<br>


Challenge:

```python
with open('/flag.txt', 'rb') as f:
    FLAG = int.from_bytes(f.read().strip(), byteorder='big')

assert FLAG < 2**1024

while True:
    print("Enter your number:")
    
    try:
        n = FLAG * int(input("> "))
        print("Your digit is:", str(n)[-1])
    except ValueError:
        print("Not a valid number! >:(")
```

<br>

Solve:

This challenge followed the recent python change - a limit on the default maximum size for int to str. <br>
More info here: <https://discuss.python.org/t/int-str-conversions-broken-in-latest-python-bugfix-releases/18889> <br>

The motivation for this change was DDOS prevention on website input fields. <br>
The limit is 10^4300, giving `ValueError: Exceeds the limit (4300) for integer string conversion` otherwise. <br>
This was a controversial change, especially in maths libraries. <br>
To disable this limit, you can do: `sys.set_int_max_str_digits(0)`

Onto the challenge:

Flag * n ~= 10^4300 will error and leak the flag. <br>
We just need to do a binary search to see when this will happen: <br>

```python
from Crypto.Util.number import long_to_bytes
from pwn import remote
io = remote("2022.ductf.dev", 30003)

def oracle(x):
    io.readuntil(b"your number:")
    io.sendline(str(x).encode())
    io.readline()
    return b"Your digit is:" in io.readline()

def solve():
    MAXINT = 10**4300
    LB = 0
    UB = MAXINT
     
    for _ in range(1000):
        mid = (LB+UB)//2
        if oracle(mid):
            LB = mid + 1
        else:
            UB = mid - 1
        print(long_to_bytes(MAXINT//mid))

solve()
#CTF{14288_bits_should_be_enough_for_anybody_:)}
```

