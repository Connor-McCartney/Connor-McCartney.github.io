---
permalink: /cryptography/other/Trying-to-crack-COD-FNV-hashes
title: Trying to crack COD FNV hashes
---

<br>


I was sent the following code from HalfInchPunisher, working with some others reverse engineering Call of Duty.

```c
#define ull unsigned long long

ull fnv64(const char* string) {
    ull hash = 0xCBF29CE484222325;
    ull prime = 0x100000001B3;

    for (int i = 0; string[i]; ++i) {
        char cur = string[i];
        if ((unsigned char)(cur - 'A') <= 25)
            cur |= 0x20;

        if (cur == '\\')
            cur = '/';

        hash ^= cur;
        hash *= prime;
    }

    return hash;
}
```

Along with a few example hashes:

```
0xC5BE054CB26B3829
0x233B0E2B30E00445
0x92A366D1A86FD4D5
0x50B2F8C43DA48808
```

<br>

Translating to sage code:

```
def fnv64(string):
    string=string.lower().replace("\\","/")
    hsh = 0xCBF29CE484222325
    prime = 0x100000001B3
    for c in string.encode():
        hsh = (hsh^^c)*prime
    return hsh % 2**64
```

Each xor operation with one of the input characters can be described as +/- some value from -128 to 128. 

Then it's a linear system mod 2**64 to solve, with n unknowns for an input string of length n.


<br>

# Using Wolfram Language

I had some troubles installing on arch, but seems easier on debian-based distros. 

You need to install the [Wolfram Engine](https://www.wolfram.com/engine/) and [WolframScript](https://www.wolfram.com/wolframscript/)

```
sudo dpkg -i WolframScript_14.0.0_LINUX64_amd64.deb
sudo ./WolframEngine_14.0.0_LINUX.sh
wolframscript
```

Some other documentation:

<https://reference.wolfram.com/language/ref/program/wolframscript.html>

<https://support.wolfram.com/45743>

<https://reference.wolfram.com/language/ref/FindInstance.html>


