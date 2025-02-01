---
permalink: /cryptography/other/nullcon2025
title: nullcon HackIM CTF Goa 2025
---

<br>


# kleinvieh

```python
from Crypto.PublicKey import RSA

flag = int.from_bytes(open('flag.txt','r').read().strip().encode())
key = RSA.generate(1024)

print(f'n = {key.n}')
print(f'c = {pow(flag, key.e, key.n)}')
phi = (key.p - 1) * (key.q - 1)
print(f'strange = {pow(phi, 2, key.n)}')
```

```
n = 123478096241280364670962652250405187135677205589718111459493149962577739081187795982860395854714430939628907753414209475535232237859888263943995193440085650470423977781096613357495769010922395819095023507620908240797541546863744965624796522452543464875196533943396427785995290939050936636955447563027745679377
c = 77628487658893896220661847757290784292662262378387512724956478473883885554341297046249919230536341773341256727418777179462763043017367869438255024390966651705078565690271228162236626313519640870358976726577499711921457546321449494612008358074930154972571393221926233201707908214569445622263631145131680881658
strange = 11519395324733889428998199861620021305356608571856051121451410451257032517261285528888324473164306329355782680120640320262135517302025844260832350017955127625053351256653287330703220294568460211384842833586028123185201232184080106340230097212868897257794101622865852490355812546172336607114197297201223620901
```

<br>



<br> <br> <br> <br> <br>

# next-level

```python
from Crypto.Util import number

def nextprime(n):
	p = n
	while True:
		if number.isPrime(p := p+1): return p

p = number.getPrime(512)
q = nextprime(p)
r = nextprime(q)
n = p*q*r
e = 0x10001
flag = int.from_bytes(open('flag.txt','r').read().encode())
c = pow(flag,e,n)
print(n)
print(c)
```

<br>














<br> <br> <br> <br> <br>

# many caesars

```python
import string
import re

text = open('text.txt','r').read().lower()
flag = open('flag.txt','r').read().strip()[4:-1].replace('_','+')
chars = string.ascii_letters + string.digits + '+/='
regex = re.compile('[' + chars + ']{5,70}')
assert re.fullmatch(regex, flag)

def caesar(msg, shift):
	return ''.join(chars[(chars.index(c) + shift) % len(chars)] for c in msg)

i = 0
count = 0
while i < len(text):
	if text[i] not in string.ascii_lowercase:
		print(text[i], end = '')
		i += 1
	else:
		j = i
		while text[j] in string.ascii_lowercase: j += 1
		print(caesar(text[i:j], chars.index(flag[count % len(flag)])), end = '')
		count += 1
		i = j
```

```
AtvDxK lAopjz /i + vhw c6 uwnshnuqjx ymfy kymhi Kyv 47+3l/eh Bs kpfkxkfwcnu Als 9phdgj9 +ka ymzuBGxmFq 6fdglk8i CICDowC, sjxir bjme+pfwfkd 6li=fj=kp, nCplEtGtEJ, lyo qeb INKLNBM vm ademb7697. ollqba lq DitCmA xzhm fx ef7dd7ii, wIvv eggiww GB kphqtocvkqp, 3d6 MAx ilsplm /d rpfkd vnloov hc nruwtAj xDxyjrx vexliv KyrE +3hc Gurz, jcemgt ixlmgw 9f7gmj5/9k obpmlkpf/ib mzp 8k/=64c ECo sj qb=eklildv. =k loGznlEpD qzC qo+kpm+obk=v, vHEEtuHKtMBHG, huk h7if75j/d9 mofs+=v, zkloh lqAkwCzioqvo rfqnhntzx fhynAnynjx b/a7 JKvrCzEx hexe BE ecwukpi 63c397. MAxLx wypujpwslz 3/c ql irvwhu 9bbcj1h9cb fsi f tswmxmzi zDGrtK ed FBpvrGL vjtqwij ixlmgep 5f8 =lkpqor=qfsb tmowuzs.
```

<br>

















<br> <br> <br> <br> <br>

# registration

```python
#!/bin/python3
from hashlib import sha256
from secret import flag
from Crypto.Util import number
import math
import os

BITS = 1024

class Pubkey(object):
	def __init__(self, n, e, a):
		self.n = n
		self.a = a
		self.e = e

	def verify(self, msg, s):
		if type(msg) == str: msg = msg.encode()
		h = number.bytes_to_long(sha256(msg).digest())
		return pow(s,self.e,self.n) == pow(self.a, h, self.n)

	def __str__(self):
		return f'n = {self.n}\na = {self.a}\ne = {self.e}'

class Key(Pubkey):
	def __init__(self, bits):
		self.p = number.getPrime(bits >> 1)
		self.q = number.getPrime(bits >> 1)
		self.n = self.p * self.q
		phi = (self.p - 1) * (self.q - 1)
		while True:
			e = number.getRandomInteger(bits)
			if math.gcd(e, phi) == 1: break
		self.e = e
		self.d = number.inverse(e, phi)
		while True:
			a = number.getRandomInteger(bits)
			if math.gcd(a, self.n) == 1: break
		self.a = a

	def sign(self, msg):
		if type(msg) == str: msg = msg.encode()
		h = number.bytes_to_long(sha256(msg).digest())
		return pow(self.a, h * self.d, self.n)

	def public(self):
		return Pubkey(self.n, self.e, self.a)

	def __str__(self):
		return f'n = {self.n}\na = {self.a}\ne = {self.e}\np = {self.p}'

if __name__ == '__main__':
	key = Key(BITS)
	print(key.public())
	while True:
		print('''Welcome to our conference reception. Can you provide a valid signature to confirm that you are alowed to participate? If not, please be patient and let the next person in the queue go fist.
		1) wait
		2) sign''')
		option = int(input('> '))
		if option == 1:
			challenge = os.urandom(BITS >> 3)
			signature = key.sign(challenge)
			print(f'Challenge: {challenge.hex()}')
			print(f'Signature: {signature}')
		elif option == 2:
			challenge = os.urandom(BITS >> 3)
			print(f'Challenge: {challenge.hex()}')
			signature = int(input('Signature: '))
			if key.verify(challenge, signature):
				print(flag)
			else:
				print('YOU SHALL NOT PASS!')
				break
		else:
			print('Invalid answer')
			break
```

<br>


