---
permalink: /cryptography/rsa/pprintable-Fall-GoN-Open-Qual-CTF-2022
title: pprintable - Fall GoN Open Qual CTF 2022
---

<br>

# Challenge

```python
from secret import flag
import string
from gmpy2 import *
from random import SystemRandom

SIZE = 2048

# read flag and construct RSA p, q
assert(len(flag) == SIZE // 8)
assert(all(c in string.ascii_letters or c in ['{', '}', '_'] for c in flag))

p = int.from_bytes(flag[:SIZE // 2 // 8].encode(), byteorder = "big")
q = int.from_bytes(flag[SIZE // 2 // 8:].encode(), byteorder = "big")
assert(is_prime(p))
assert(is_prime(q))

# generate textbook RSA key
N = p*q
phi = (p - 1) * (q - 1)
e = 0x10001
d = int(gmpy2.invert(e, phi))

pt = int.from_bytes(b"flag{this_is_fake_flag_:P}", byteorder = "big") 
ct = pow(pt, e, N)

# generate random mask and redact p,q
p_mask = 0
q_mask = 0
cryptogen = SystemRandom()
for i in range(SIZE // 2):
    # the SOTA paper says u need 50%
    # not a chance :p
    if cryptogen.random() < 0.35:
        p_mask |= 1
    if cryptogen.random() < 0.35:
        q_mask |= 1
    p_mask <<= 1
    q_mask <<= 1

p_redacted = p & p_mask
q_redacted = q & q_mask

print("N  : 0x%x"%N)
print("e  : 0x%x"%e)

print("p_redacted : 0x%x"%p_redacted)
print("p_mask : 0x%x"%p_mask)
print("q_redacted : 0x%x"%q_redacted)
print("q_mask : 0x%x"%q_mask)

print("ct : 0x%x"%ct)
```

<br>

Output:

<br>

```
N  : 0x12376eadc9b0bd1f13fa9d904f5a1a75bb7ddaaa77ec5b1e8dec4cb7532b662fcc63a0dfa982e1702be449c9b295bf7a0b7c6ba3dc7aaf3856d681601e723aa3bce3e0cd064793a9c6b00eb01d3e3f0fbceddb208cba2598d9d6a35f3cf8623a1389686807fb5f8f53dd0a7f544c02d030f498f7aa315b7547783399bc88cd3e2859b6786b858a35593537ead5a0cc48401a24cefe6ac6997035f6571af098d5d5b24313437fd89d22cce7fa5907d73c219b609eeea9bcffab0f18504e1d2ed5669752e21dd17b57ea5cf6e6efa76cd965e4589539dc087e152fb4d3f1f90edcdcab22b71b326a3e7e0674f8820a24aa3be15756db2e908d434b80419061bf45
e  : 0x10001
p_redacted : 0x50b4040146040415a04084000094153182141460200401063040440024200046055600042240040410248014e00410444640240166000001e09141101084025181052000c30004260000406100601226058401613084a0040492001040404620100401344612000215221412811086840005d06001060000008460040025000
p_mask : 0x1250b70401c6444455a8418d2800945d3182dc1c7060a4010630c0c4282c2a0047575e8084aa4207ac592ca034e02e78445640f40366020089e0b9791119940b53818d2842c3082ea70818e0610a601b2e35844169708ca00404931912e04046e01004893e4632c80a1da23c9ab310868d402dd0600307283300cd680c1a25602
q_redacted : 0x80902304402050a7145440048082208004041205b60014000102340106007002a240b0108404005604000190060092010010004504c2104002100140009020270500022101530484551206642004c1424200000202040042210204c4143704000480101004809114629230312040040000600400420520943204412216404
q_mask : 0x1aa0809033046833d9e7945e420480822090ac0c1a35bf00b48a21223c23060070c2a240b0328c4c235e0408819817209a11531101c50cd21a6012309b40c292302f05000221c353a5845f126e65210ec9c24a0001820284004bf1a206c45637b4500680581894d0d1d46bb2b039a2e84d008a604508420d219c32166b2276c04
ct : 0x97090fc71e4c4c7fe52fb9c5cafde7bae8cf5f911c2755174f3a61515f475c7000d127e23ad99498bd58078abe2890fe40c64067116c66be74ac5422e731905103f4ecc4ae6cf9478580d6fb373744b897caf2b95f01531b626afb46eb88c0f5f419635a27f903ab8ffc55094e015008cbb9520f07755da279226fefa8859bfef694b86ca3fdf88042361d18ecb7ae1ecf98041140b3f167687f45e3da914ee35f9d345782438018310da609578a1047a99a9c54ff846eb2017ac26a0cfb8f5e542c0c7feba904e0ff15a6e2712c2135f9c80b057185cd31a8e9e5371194d063776bdf3537837c705d3761dd6f0ec9419034c294914015bc0e3fbea474fdc15
```

<br>

Solve:

We use the limited charset and the masks to prune:

<br>

```python
import string
from Crypto.Util.number import *
from tqdm import trange

N  = 0x12376eadc9b0bd1f13fa9d904f5a1a75bb7ddaaa77ec5b1e8dec4cb7532b662fcc63a0dfa982e1702be449c9b295bf7a0b7c6ba3dc7aaf3856d681601e723aa3bce3e0cd064793a9c6b00eb01d3e3f0fbceddb208cba2598d9d6a35f3cf8623a1389686807fb5f8f53dd0a7f544c02d030f498f7aa315b7547783399bc88cd3e2859b6786b858a35593537ead5a0cc48401a24cefe6ac6997035f6571af098d5d5b24313437fd89d22cce7fa5907d73c219b609eeea9bcffab0f18504e1d2ed5669752e21dd17b57ea5cf6e6efa76cd965e4589539dc087e152fb4d3f1f90edcdcab22b71b326a3e7e0674f8820a24aa3be15756db2e908d434b80419061bf45
p_redacted = 0x50b4040146040415a04084000094153182141460200401063040440024200046055600042240040410248014e00410444640240166000001e09141101084025181052000c30004260000406100601226058401613084a0040492001040404620100401344612000215221412811086840005d06001060000008460040025000
p_mask = 0x1250b70401c6444455a8418d2800945d3182dc1c7060a4010630c0c4282c2a0047575e8084aa4207ac592ca034e02e78445640f40366020089e0b9791119940b53818d2842c3082ea70818e0610a601b2e35844169708ca00404931912e04046e01004893e4632c80a1da23c9ab310868d402dd0600307283300cd680c1a25602
q_redacted = 0x80902304402050a7145440048082208004041205b60014000102340106007002a240b0108404005604000190060092010010004504c2104002100140009020270500022101530484551206642004c1424200000202040042210204c4143704000480101004809114629230312040040000600400420520943204412216404
q_mask = 0xaa0809033046833d9e7945e420480822090ac0c1a35bf00b48a21223c23060070c2a240b0328c4c235e0408819817209a11531101c50cd21a6012309b40c292302f05000221c353a5845f126e65210ec9c24a0001820284004bf1a206c45637b4500680581894d0d1d46bb2b039a2e84d008a604508420d219c32166b2276c04

charset = string.ascii_letters + "_{}"
sol = {("", "")}
for j in trange(1, 129):
    cur_sol = set()
    m = 2**(8*j)

    for psol, qsol in sol:
        for pi in charset:
            pp = f"{ord(pi):08b}" + psol
            for qi in charset:
                qq = f"{ord(qi):08b}" + qsol
                if p_mask & int(pp, 2) != p_redacted % m:
                    continue
                if q_mask & int(qq, 2) != q_redacted % m:
                    continue
                if int(qq, 2) * int(pp, 2) % m != N % m:
                    continue
                cur_sol.add((pp, qq))
    sol = cur_sol


for p, q in list(sol):
    p = long_to_bytes(int(p, 2))
    q = long_to_bytes(int(q, 2))
    print(p+q)

# GoN{This_Flag_iS_cOnSTrUcTEd_wITh_pURe_ASCII_lATTers_aNd_IT_also_RSA_seCert_P_and_Q_so_we_nEEd_some_Gibberish_like__aPelDKfjpNXiAHIFudNEKsM__iNcLuded_becAUse_p_and_q_ShOuld_be_prIme_nuMBer_sORRy_for_the_inCONvenIEncE_but_i_tHINk_THIs_is_SUpEr_cOol_iSnT_it}
```