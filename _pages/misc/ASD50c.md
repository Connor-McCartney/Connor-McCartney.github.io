---
permalink: /misc/ASD50c
title: Solving the codes from Australian Signals Directorate cyber-spy agency's 75th anniversary 50c coin with UQ Cyber Squad
---

<br>

@Mirai-Miki first posted the link about the new coin - <https://www.abc.net.au/news/2022-09-01/act-spy-agency-releases-coin-with-secret-code/101391964>

@Chiefclapcheek figured out that the back of the coin had braille under some letters, which when put in order spelled 'atbash'.

![image](https://raw.githubusercontent.com/Connor-McCartney/Connor-McCartney.github.io/main/_pages/misc/images/backofcoin.png)

![image](https://raw.githubusercontent.com/Connor-McCartney/Connor-McCartney.github.io/main/_pages/misc/images/braille.png)

This is a reference to the [atbash cipher](https://www.dcode.fr/atbash-cipher) which @h4sh and I found decodes the outer ring:

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
