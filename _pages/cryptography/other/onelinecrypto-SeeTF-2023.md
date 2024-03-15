---
permalink: /cryptography/other/onelinecrypto-SeeTF-2023
title: onelinecrypto - SeeTF 2023
---

<br>
<br>

Challenge:

```python
assert __import__('re').fullmatch(r'SEE{\w{23}}',flag:=input()) and not int.from_bytes(flag.encode(),'big')%13**37
```

Other writeups:


Author's (neobeo) <https://demo.hedgedoc.org/s/DnzmwnCd7>

<https://nush.app/blog/2023/06/21/see-tf-2023/>

<https://nush.app/blog/2023/06/21/see-tf-2023/>

<https://blog.maple3142.net/2023/06/12/seetf-2023-writeups/>

