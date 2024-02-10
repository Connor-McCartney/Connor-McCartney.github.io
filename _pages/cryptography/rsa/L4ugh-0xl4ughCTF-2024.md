---
permalink: /cryptography/rsa/L4ugh-0xl4ughCTF-2024
title: L4ugh - 0xl4ughCTF 2024
---

<br>

[Challenge Files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2024/0xL4ugh/L4ugh)

<br>

A nice challenge written by my friend mindflayer and Bebo!

This was a 3-part challenge, finding d_good, finding d_evil, and a CBC bit flipping attack.

To find d_good you can send the biggest number allowed then divide by it, negating <br>
the comparatively small error error constant added.

Finding d_evil was interesting. We have pairs of n and e generated with the same d.
