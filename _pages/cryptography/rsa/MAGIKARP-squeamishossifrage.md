---
permalink: /cryptography/rsa/MAGIKARP-squeamishossifrage
title: MAGIKARP - squeamishossifrage
---

<br>

[Challenge](https://github.com/zerosumsecurity/squeamishossifrage/tree/main/MAGIKARP)

<br>

Looking at the .crt we see e=1.

Now we need to decrypt the SMIME flag.

```
wget https://raw.githubusercontent.com/zerosumsecurity/squeamishossifrage/main/MAGIKARP/flag.encrypted
openssl smime -in flag.encrypted -pk7out -out flag.pk7
openssl pkcs7 -in flag.pk7 -print

PKCS7: 
  type: pkcs7-envelopedData (1.2.840.113549.1.7.3)
  d.enveloped: 
    version: 0
    recipientinfo:
        version: 0
        issuer_and_serial: 
          issuer: C=EU, O=Squeamish Ossifrage, OU=RSA, CN=Dodgy Certificate Service
          serial: 0x6573F91886BC363E3CC77F6D1F82D1BB6260282A
        key_enc_algor: 
          algorithm: rsaEncryption (1.2.840.113549.1.1.1)
          parameter: NULL
        enc_key: 
          0000 - 00 02 6f 44 ba 0b e7 f2-92 0c a3 bf ce 5d a4   ..oD.........].
          000f - 0d 86 07 19 d6 2f 09 6f-e4 61 5a 9c 35 87 65   ...../.o.aZ.5.e
          001e - 80 4f 4a 5f 6a 08 f9 bc-4e f4 38 0e a5 5d 76   .OJ_j...N.8..]v
          002d - b5 f2 ee d4 68 7e c0 3c-96 13 3b 8b 27 69 8a   ....h~.<..;.'i.
          003c - 3e b3 08 b8 d6 60 a2 95-fb 16 08 50 29 d3 e0   >....`.....P)..
          004b - 50 e8 a8 a5 01 f7 52 30-cb 83 07 fd a0 8e 65   P.....R0......e
          005a - c0 30 c6 fc 73 00 bb e5-67 73 a4 40 5c c4 90   .0..s...gs.@\..
          0069 - a4 42 ad f6 62 ed 5e d9-96 cc 0a c2 98 7f e0   .B..b.^........
          0078 - 4d bf 7e d2 29 75 c2 ac-                       M.~.)u..
    enc_data: 
      content_type: pkcs7-data (1.2.840.113549.1.7.1)
      algorithm: 
        algorithm: aes-256-cbc (2.16.840.1.101.3.4.1.42)
        parameter: OCTET STRING:
          0000 - a4 20 a6 65 fd ae 57 b5-d2 7d d1 6e 5a 96 3e   . .e..W..}.nZ.>
          000f - e6                                             .
      enc_data: 
        0000 - 83 57 ab 47 53 3f 9e b8-35 71 9e 5d 2b 3b 18   .W.GS?..5q.]+;.
        000f - cc de 47 08 44 44 d0 c7-c2 e8 b9 4f 04 a9 9f   ..G.DD.....O...
        001e - 3e 0e 52 03 1d 6e e4 2a-16 a4 22 66 f1 5b de   >.R..n.*.."f.[.
        002d - 7f 03 58                                       ..X
-----BEGIN PKCS7-----
MIIBiAYJKoZIhvcNAQcDoIIBeTCCAXUCAQAxggEQMIIBDAIBADB1MF0xCzAJBgNV
BAYTAkVVMRwwGgYDVQQKDBNTcXVlYW1pc2ggT3NzaWZyYWdlMQwwCgYDVQQLDANS
U0ExIjAgBgNVBAMMGURvZGd5IENlcnRpZmljYXRlIFNlcnZpY2UCFGVz+RiGvDY+
PMd/bR+C0btiYCgqMA0GCSqGSIb3DQEBAQUABIGAAAJvRLoL5/KSDKO/zl2kDYYH
GdYvCW/kYVqcNYdlgE9KX2oI+bxO9DgOpV12tfLu1Gh+wDyWEzuLJ2mKPrMIuNZg
opX7FghQKdPgUOiopQH3UjDLgwf9oI5lwDDG/HMAu+Vnc6RAXMSQpEKt9mLtXtmW
zArCmH/gTb9+0il1wqwwXAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBKgQQpCCmZf2u
V7XSfdFuWpY+5oAwg1erR1M/nrg1cZ5dKzsYzN5HCERE0MfC6LlPBKmfPg5SAx1u
5CoWpCJm8VvefwNY
-----END PKCS7-----
```
