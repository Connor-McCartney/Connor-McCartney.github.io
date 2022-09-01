---
permalink: /misc/ASD50c
title: Solving the codes from Australian Signals Directorate cyber-spy agency's 75th anniversary 50c coin with UQ Cyber Squad
---

<br>

@Mirai-Miki first posted the link about the new coin - <https://www.abc.net.au/news/2022-09-01/act-spy-agency-releases-coin-with-secret-code/101391964>

@Chiefclapcheek figured out that the back of the coin had braille under some letters, which when put in order spelled 'atbash'.

![image](https://raw.githubusercontent.com/Connor-McCartney/Connor-McCartney.github.io/main/_pages/misc/images/backofcoin.png)

![image](https://raw.githubusercontent.com/Connor-McCartney/Connor-McCartney.github.io/main/_pages/misc/images/braille.png)

This is a reference to the [atbash cipher](https://www.dcode.fr/atbash-cipher) which @h4sh and I found decodes the outer ring on the front of the coin:

![image](https://raw.githubusercontent.com/Connor-McCartney/Connor-McCartney.github.io/main/_pages/misc/images/frontofcoin.png)

DVZIVZFWZXRLFHRMXLMXVKGZMWNVGRXFOLFHRMVCVXFGRLM . URMWXOZIRGBRM7DRWGSC5WVKGS

becomes WE ARE AUDACIOUS IN CONCEPT AND METICULOUS IN EXECUTION . FIND CLARITY IN 7 WIDTH X 5 DEPTH

This is a hint on how to solve the inner ring - BGOAMVOEIATSIRLNGTTNEOGRERGXNTEAIFCECAIEOALEKFNR5LWEFCHDEEAEEE7NMDRXX5

@LegallyBearded figured out you split it in half then read down the columns:

```
BGOAMVO
EIATSIR
LNGTTNE
OGRERGX
NTEAIFC
---------------------------------------
ECAIEOA
LEKFNR5
LWEFCHD
EEAEEE7
NMDRXX5
```

Which reads: BELONGING TO A GREAT TEAM STRIVING FOR EXCELLENCE WE MAKE A DIFFERENCE XOR HEX A5D75

I transcribed the hex in the middle of the coin:

```
E3B8287D4290F7233814D7A47A291DC0F71B2806D1A53B311CC4B97A0E1CC2B93B31068593332F10C6A3352F14D1B27A3514D6F7382F1AD0B0322955D1B83D3801CDB2287D05C0B82A311085A033291D85A3323855D6BC333119D6FB7A3C11C4A72E3C17CCBB33290C85B6343955CCBA3B3A1CCBB62E341ACBF72E3255CAA73F2F14D1B27A341B85A3323855D6BB333055C4A53F3C55C7B22E2A10C0B97A291DC0F73E3413C3BE392819D1F73B331185A3323855CCBA2A3206D6BE3831108B
```

@SirNutty mostly solved the next one through bruteforce, then later @h4sh found that the xor key 'A5D75' repeats.

```py
c = 'E3B8287D4290F7233814D7A47A291DC0F71B2806D1A53B311CC4B97A0E1CC2B93B31068593332F10C6A3352F14D1B27A3514D6F7382F1AD0B0322955D1B83D3801CDB2287D05C0B82A311085A033291D85A3323855D6BC333119D6FB7A3C11C4A72E3C17CCBB33290C85B6343955CCBA3B3A1CCBB62E341ACBF72E3255CAA73F2F14D1B27A341B85A3323855D6BB333055C4A53F3C55C7B22E2A10C0B97A291DC0F73E3413C3BE392819D1F73B331185A3323855CCBA2A3206D6BE3831108B'
k = 'A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5D75A5'
m = int(c, 16) ^ int(k, 16)
print(bytes.fromhex(hex(m)[2:]))
```

It decodes to 'For 75 years the Australian Signals Directorate has brought together people with the skills, adaptability and imagination to operate in the slim area between the difficult and the impossible.'

<br>

Then we started looking at the different shadings/colours. <br>
The inner circle has colours WBBBBBWWBWBBWWWBBBWBBWBBBBWWWWBBBWBWWWBBWBBWWBBWBBWWBBBBBWWBBWBBWWBBWB <br>
@lol! found if you replace the white with '1' and the black with '0' then convert using binary with byte length 7, it decodes to 'ASDCbr2022'


