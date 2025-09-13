---
permalink: /misc/gdb
title: gdb
---

<br>



<https://sourceware.org/gdb/current/onlinedocs/gdb.html/index.html>

<https://web.archive.org/web/20250101052732/https://users.umiacs.umd.edu/~tdumitra/courses/ENEE757/Fall15/misc/gdb_tutorial.html>

<https://www.brendangregg.com/blog/2016-08-09/gdb-example-ncurses.html>


<br>

# install pwndbg

```
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```


# x - examine

`x/<n><u><f> <address>`

u - unit size (b: 1 byte, h: 2 bytes, w: 4 bytes, g: 8 bytes)

f - format (d: decimal, x: hex, s: string, i: instructions)

n -  number of elements



