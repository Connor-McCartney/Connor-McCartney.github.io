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

# kleinvieh_2

```python
#!/usr/bin/env python3
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
import math

# Utility functions
def chunks(l : list, n : int):
	"""Yield successive n-sized chunks from l."""
	for i in range(0, len(l), n):
		yield l[i:i + n]

# Encryption Methods

def encrypt1(message : bytes, key):
	return pow(bytes_to_long(message), key.e, key.n)

def encrypt2(message : bytes, key):
	r = 688234005348009046360676388021599552323079007705479727954148955984833460337936950913921276804334830417982234720038650432729780498514155995618937412575604196815690605161835755609341381092145548153312943119696398326144902639226831471200542337105282064399184931676924592908530791494346900227871404063095592748764296028255530577278656680463782655139421219302422899667665339277824718421901831817043159552132252016945226370677278067424506514993298100924479619565269428391036310378044733517453768164252655931111202089432697078947184486267865943138659836155939343134738408972426979329158506027280653209318479413895259774319848662706808171929571545923310500352950348748809789292920278241362015278963315481777028997344480172010960294002098578989469089294022590134823913936869548907125294447477430739096767474026401347928008150737871869441842515706902681140123776591020038755234642184699856517326004574393922162918839396336541620212296870832659576195010466896701249003808553560895239860454162846759635434691728716499056221797005696650174933343585361153344017021747827389193405667073333443569659567562247406283282451284155149780737904760989910944550499316655128394899229284796584787198689342431338201610314893908441661953172106881929330452489260
	return pow(bytes_to_long(message) * r, key.e, key.n)

def encrypt3(message : bytes, key):
	bytelength = int(math.floor(math.log2(key.n))) // 8
	msg = message + b'\x00' * (bytelength - len(message))
	return pow(bytes_to_long(msg), key.e, key.n)

def encrypt4(message : bytes, key):
	bytelength = int(math.floor(math.log2(key.n))) // 8
	msg = message * (bytelength // len(message))
	return pow(bytes_to_long(msg), key.e, key.n)

def encrypt5(message : bytes, key):
	bytelength = int(math.floor(math.log2(key.n))) // 8
	msg = b'\x42' * (bytelength - len(message)) + message
	return pow(bytes_to_long(msg), key.e, key.n)

# Actual code
flag = open('flag.txt','r').read()
messages = [x for x in chunks(flag.encode(), len(flag) // 5 + 1)]

key = RSA.generate(4096, e = 3)
key_file = open('pubkey.pem','wb')
key_file.write(key.public_key().export_key())
key_file.close()

encryptors = [encrypt1,encrypt2,encrypt3,encrypt4,encrypt5]

for i in range(5):
	print(encryptors[i](messages[i], key))
```

```
220063927409019701680780388734859413263649938528559880958114989945319210396443096153070875125175228115415476201776095239222264863
521405777679638898956934268538900625825553438750301296652588113926908675649695287473044872094704614120486323959657990026640254596060659622526156708812669359650586620385290808935734592790788255073585330621151468871219769656595135843333814407503403584485725875093573131958504623569333490646639116961719078216840229603919536018487825851994866357917761987217050792416697381377048912395473353778387941958191907824408107449076068401916848269614839157102521989010679392116485801486351905021880108912590420172605418475794616003449288680484874497236175444664128438401914724753429360434711903099273327857734995750524336685921743399501618966233467673179877216701974657036419446491274854437281396070824372634560507303755215464570159167837973755757084277460889038540426254099700613477619367190997235567982845416706558020882785247647017658533190054489579620395565959077232929730085201031313238724372408560517067025821200011117585158799293570307490792480672057216647059928346781983773928742745961020992758462787355967282442061725370293489410415806016306004266400903317110818168429756442671778827765363252714782616931406456862197207387559816797319132734318242504254436838880072071853192476696183220292931118231156006566093505435792459195491243680582
270666484654665630744901461996006692323963839982688652821336211084979467239347411813160298980515940583603861222174521984995420008548684262439808167328926021870579303960012771121601180529687766238396064375729105115543248938593316359682370849163035376370382430086321848989469101241917690539277074390985259902303859203469942292526312785642432913613936993258827179590899881832319079212987637373648192635781867448864854757206430089991579140087742146982306295873762255307312524837239897502872553828380739799963200435212855355849421115331904398013024635259514540481471626803307520164323612306097337438109957993918779265436327033558060626053354750562352860044802675727693412211125966360236444057953485024215560142475510160722114624532935356913983972915673608523025209720167213909179022327299978019112977846926119199262414918029479523990318896183663433071251579236571042002734675157891234966022932698905198698241706452025453847010887618278823570050783989170662300961633292513523806788091889082274722372602239592372048577727269817482906420208931626412130427401917267155522492175168008656904232528370893411707370782832090829602128710489070166301148107529844470225377087526762510454613609000260941022095648201987928579356978933393880920171979201
653824340069025689137734254884130538700629136163559226740194794484993327658776187767570065320577134162743283784425272380809589160993088925874733196055173409287931015748252064633449072261545303183579447460502965342804624603405929157397131141984984644568357653302213965819415468460642952197339991556281367534783709497954301841184449070203282829556818406681886900718807834059676277878423047814575995317125009067646248518224341963179051812872833920966444865854397107596362642091691676816880789051432546280982801936460897107739053704289586862815777802365195344200436339914632247470287475059508482642321374344266084746769130713777040613388188063244264539412036380560226898399218628361640805872727932488302521211097971713325651815102241321497845489911517697687601337373561866169629605144418239966598946278151568343055898100847891792937851579379932984962575775149818916217268297467279875725571404166944999117855879952146915514369003878816227211205583465391314024099614444033724650197415698616726563650695337089763944873372957911180655004798934831152909017151923470147174567931032793367193038245769647005250292165097213630935925441110568790329108402080201984414111112552177466252777781418725448757243067372449888316330317213717511659267093522
358008688390962979576377899144327321078101097951911268175317488500603502519487932330612462905624620597194558963905078036617959827652774950608159539755872698070336695988156123259549872787213397592148258199055613243895883287122890753360508292871837174063088420693224462093920149982044282287843545879889673811146267351528090047294284591799007589644031290908451176760853222636619363811207185693725681140126798792027873548626157363148637874670590965485611082128311321694683523699469128409485949494113757646949983087406842230923148769118322570130431421259760535420603207584288801345366412235455743468488327636151425392848303200702882860489019370153190810988494600882544600108525238483037309140333051358221984674540701977879624246387893765464282113949391789532777484259814371861241414118348867987309273292578129887971446610687731851915056696448523460974558006120340055071716623978233935275849865817975522109696101884471525506261697387468489779620579480299246665603825623773259263912587161909414417437045900004826755951647391749631385635652448151832357232824962202646901774457696625192040117636828038808343932086478692164048901540300465526784540912169577834838256728624868904132298644241575543460006379361856217382572895303794378838795856964
```

```
-----BEGIN PUBLIC KEY-----
MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAq0qupn0dQPB2KBxkqKbH
qVdlQVInAL+PVtOIqiPfAKuomeiAPFqSxYnVszx8OX7esMulhF/JXERl17Glc7nr
1f4g5TqCRBdLjn7L5UFQfnTDgs0H0eEEXkDo6ujFrP7SCCjwm4u0YQUE14nIFDk2
eLNj7UHXNXvsTLhdJ6cahmMQ0UpcNLvJ2Utq+mPnxHQ4t8WfAe9LeMGSwyHvN6aW
33crJlWIA7q+USLxqQjfOVX2/nGMh/hUZiWkIWrUu5DrbN187s1UuFp/XMsgfTFM
gAFwe8yzwOS5NBc97H4hBechDSCIpUwYd07pkmPEon7V9sUuQasM84UqgzvSQBTF
vP8uKlzZpnoMIVFQJ1iPOUOsf6RYEhw2rgywIKgWILDUutcrBhMm/sZyYR1IqiYc
QBUaJ9jeCQ8pJk5GtTb2B/MDDlazW37iQmPopUGuaRAkWRVpSENC04/3pa57g0R3
jKffVevsNNOPcdVveZ9CNUJ36ckCHMkVjhtwTj3ChhCJkq0EJsmFZcSMe5dWtUEs
6tZm/OXkyCCIkJW2+9bv6fDxAuGtY6VKHKDYeFS1nfufA8fI7L022O++D9nkLnBX
bbi8dinhS9SfTS9GqR5mbEm5NvGT0bG74YbYO4Oy1GPThJOtMXVuNh1qevzDgKKF
PQlPTql78u4Zhw+T2ukQPGsCAQM=
-----END PUBLIC KEY-----
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





<br> <br> <br> <br> <br>

# coinflip

```python
#!/usr/bin/env python3
import os
import sys
from Crypto.Util.number import bytes_to_long, getRandomNBitInteger
import math

flag = open('flag','r').read().strip()
N = 64

def log(*err_messages):
	'''function for debugging purposes'''
	logs = open('err.log','a')
	for msg in err_messages:
		if type(msg) == bytes: msg = hexlify(msg).decode()
		logs.write(msg)
	logs.write('\n=====\n')
	logs.close()

class CRG(object):
	"""Cubic Random Generator"""

	def __init__(self, n):
		'''n - bitlength of state'''
		self.n = n
		self.m = getRandomNBitInteger(n)
		while True:
			self.a = bytes_to_long(os.urandom(n >> 3)) % self.m # n/8 bytes
			if math.gcd(self.a, self.m) == 1: break
		while True:
			self.state = bytes_to_long(os.urandom(n >> 3)) % self.m # n/8 bytes
			if math.gcd(self.state, self.m) == 1: break
		self.buffer = []

	def next(self):
		if self.buffer == []:
			self.buffer = [int(bit) for bit in bin(self.state)[2:].zfill(self.n)]
			self.state = self.a * pow(self.state, 3, self.m) % self.m
			#log('new state: ', self.state)
		return self.buffer.pop(0)

def loop():
	balance = 2
	coin = ['head','tails']
	crg = CRG(N)
	while True:
		if balance == 0:
			print('I do not talk to broke people.')
			return
		if balance >= 1000000000:
			print(f'Wow, here is your flag: {flag}')
			return
		print(f'How much do you want to bet? (you have {balance})')
		sys.stdout.flush()
		amount = int(sys.stdin.buffer.readline().strip())
		if amount > balance or amount <= 0:
			print('Ugh, cheater!')
			return
		print('What is your bet?')
		sys.stdout.flush()
		bet = sys.stdin.buffer.readline().strip().decode()
		if bet == coin[crg.next()]:
			print('you win')
			balance += amount
		else:
			print('you lose')
			balance -= amount

if __name__ == '__main__':
	try:
		loop()
	except Exception as err:
		print('Something went wrong')
		log('ERROR: ', repr(err))
```

<br>

















<br> <br> <br> <br> <br>

# Matrixfun

```python
import sys
import pwn
import pickle
import base64
import hashlib
import random
import numpy as np
from numpy._typing import NDArray
from gmpy2 import mpz
from typing import Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def mpow(a: NDArray[Any], e: int, p: mpz):
    n = a.shape[0]
    c: NDArray[Any] = np.identity(n, dtype=object) // mpz(1)
    for i in range(e.bit_length(), -1, -1):
        c = (c @ c) % p
        if e & (1 << i):
            c = (c @ a) % p
    return c


def dec(key: bytes, iv: bytes, ciphertext: bytes) -> str:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode()


def main():
    r = pwn.remote(sys.argv[1], int(sys.argv[2]))
    r.send(base64.b64encode(b"g"))
    r.send(b"\r\n")

    msg = r.recv()
    p, g, gorder = pickle.loads(base64.b64decode(msg))
    print(gorder)
    a = random.randint(0, gorder)
    A = mpow(g, a, p)
    r.send(base64.b64encode(pickle.dumps(A)))
    r.send(b"\r\n")

    msg = r.recv()
    B, iv, cipher = pickle.loads(base64.b64decode(msg))

    K = mpow(B, a, p)
    h = hashlib.sha256()
    h.update(str(K).encode())
    digest = h.digest()
    print(dec(digest, iv, cipher))

    r.send(base64.b64encode(b"kthxbye"))
    r.send(b"\r\n")
    print(r.recv().decode("utf-8").strip()[::-1])


if __name__ == "__main__":
    main()
```

<br>

