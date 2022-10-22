---
permalink: /cryptography/other/cryptoverse-CTF-2022
title: cryptoverse CTF 2022
---

<br>

[Challenge Files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2022/cryptoversectf)

<br>

# Warmup 1

Decode the following ciphertext: cGlwZ3N7cG5yZm5lXzY0X3Nnan0=.

This is just base64 and then rot13 <br>
<https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)ROT13(true,true,false,13)&input=Y0dsd1ozTjdjRzV5Wm01bFh6WTBYM05uYW4w>

cvctf{caesar_64_ftw}

<br>

# Warmup 2

First described by Giovan Battista Bellaso in 1553, this cipher is easy to understand and implement, but it resisted all attempts to break it until 1863, three centuries later.

Remember: The Key to success is determination.

fzvxw{hqtegmfr_lw_msf_scrslg_kvwlhyk_fpr_kxg?}

<br>

<https://www.dcode.fr/vigenere-cipher>

cvctf{vigenere_is_too_guessy_without_the_key?}

<br>

# Warmup 3

You should recognize this instantly.

-.-. ...- -.-. - ..-. -- ----- .-. ..... ...-- .. ... -. ----- - ..... ----- ..-. ..- -.

Note: Add { and } around the flag. Flag is all lower case.

<br>

<https://www.dcode.fr/morse-code>

CVCTFM0R53ISN0T50FUN

cvctf{m0r53isn0t50fun}

<br>

# Warmup 4

Last warmup. You should get it fast if you use any social media.

Ｉn sｃｉencｅ fіctіοｎ, ｍetａνerse ｉs ｉtｅrａtiｏｎоf the Iｎternｅｔ as a sⅰｎgｌe, universal and immersive virtual world that is facilitated by the use of virtual reality and augmented reality headsets.

Note: Wrap the message you decoded in cvctf{}.

Note 2: This challenge involves some steganography tool related to a social media.

<br>

https://holloway.nz/steg/

cvctf{secretsaretobeh1dd3n}

<br>

# Substitution

Substitution is a cryptographic technique where a plaintext is replaced by a ciphertext. The ciphertext is a substitution of the plaintext.

Here is a very simple CTF-related substitution cipher. Find out the flag.

Hxpkdiz kcz Osxe ja x apzhjxs ljvr go jvogimxkjgv azhdijkf hgmpzkjkjgva. Kcziz xiz kcizz hgmmgv kfpza, Uzgpxirf, Xkkxhl Rzozvhz xvr mjyzr.
Jo fgd cxwz ojedizr gdk kcz xqgwz mzaaxez, cziz ja fgdi osxe, pszxaz xrr hdisf qixhlzka qzogiz adqmjaajgv: hwhkoxwzifajmpszadqakjkdkjgv

<br>

<http://quipqiup.com/>

cvctf{averysimplesubstitution}

<br>

# RSA 1

The n is so large that it's not possible to factor it. Or is it?

```py
n = 0x7c05a45d02649367ebf6f472663119777ce5f9b3f2283c7b03471e9feb1714a3ce9fa31460eebd9cd5aca7620ecdb52693a736e2fcc83d7909130c6038813fd16ef50c5ca6f491b4a8571289e6ef710536c4615604f8e7aeea606d4b5f59d7adbec935df23dc2bbc2adebbee07c05beb7fa68065805d8c8f0e86b5c3f654e651
e = 0x10001
ct = 0x35b63f7513dbb828800a6bcd708d87a6c9f33af634b8006d7a94b7e3ba62e6b9a1732a58dc35a8df9f7554e1168bfe3de1cb64792332fc8e5c9d5db1e49e86deb650ee0313aae53b227c75e40779a150ddb521f3c80f139e26b2a8880f0869f755965346cd28b7ddb132cf8d8dcc31c6b1befc83e21d8c452bcce8b9207ab76e
```

<br>

In this challenge the author simply uploaded the factors of n to <http://factordb.com>

```py
n = 0x7c05a45d02649367ebf6f472663119777ce5f9b3f2283c7b03471e9feb1714a3ce9fa31460eebd9cd5aca7620ecdb52693a736e2fcc83d7909130c6038813fd16ef50c5ca6f491b4a8571289e6ef710536c4615604f8e7aeea606d4b5f59d7adbec935df23dc2bbc2adebbee07c05beb7fa68065805d8c8f0e86b5c3f654e651
e = 0x10001
ct = 0x35b63f7513dbb828800a6bcd708d87a6c9f33af634b8006d7a94b7e3ba62e6b9a1732a58dc35a8df9f7554e1168bfe3de1cb64792332fc8e5c9d5db1e49e86deb650ee0313aae53b227c75e40779a150ddb521f3c80f139e26b2a8880f0869f755965346cd28b7ddb132cf8d8dcc31c6b1befc83e21d8c452bcce8b9207ab76e
p = 8156072525389912369788197863285751656042515380911795404436333529629416084362735262281722179416240983448945672233749861517470671156357917601583268804973543
q = n//p
d = pow(e, -1, (p-1)*(q-1))
flag = long_to_bytes(pow(ct, d, n))
print(flag)
#b'cvctf{f4c70rDB_15_p0w3rfu1}'
```

<br>

# RSA 2
