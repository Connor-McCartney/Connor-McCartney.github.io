---
permalink: /cryptography/other/CRYPTO-CTF-2024
title: CRYPTO CTF 2024
---

<br>
<br>

# Alibos


# Beheaded


# Mashy

```python
#!/usr/bin/env python3

import sys
from hashlib import md5
from binascii import *
from secret import salt, flag

def die(*args):
	pr(*args)
	quit()

def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()

def sc():
	return sys.stdin.buffer.readline()

def xor(s1, s2):
	return bytes([s1[_] ^ s2[_] for _ in range(len(s1))])

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, ".: Hi all, she did Mashy, you should do it too! Are you ready? :. ", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")

	REC = []
	cnt, STEP = 0, 7
	sh = md5(salt).digest()
	
	while True:
		pr(border, f'Please send your first input:  ')
		d1 = sc().strip()
		pr(border, f'Please send your second input: ')
		d2 = sc().strip()
		try:
			d1 = hexlify(unhexlify(d1))
			d2 = hexlify(unhexlify(d2))
			h1 = md5(unhexlify(d1)).digest()
			h2 = md5(unhexlify(d2)).digest()
		except:
			die(border, 'Your inputs are not valid! Bye!!!')
		if d1 != d2 and d1 not in REC and d2 not in REC:
			if md5(xor(d1, d2)).hexdigest() != 'ae09d7510659ca40eda3e45ca70e9606':
				if hexlify(xor(xor(h1, h2), sh)) == b'a483b30944cbf762d4a3afc154aad825':
					REC += [d1, d2]
					if cnt == STEP:
						die(border, f'Congrats! the flag: {flag}')
					pr(border, 'Good job, try next level :P')
					cnt += 1
				else:
					die(border, 'Your input is not correct! Bye!')
			else:
				die(border, 'No this one! Sorry!!')
		else:
			die(border, 'Kidding me!? Bye!!')

if __name__ == '__main__':
	main()
```

