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



<br>

<br>


# commands list

`disas/disass/disassemble`, also use `set disassembly-flavor intel` beforehand

`attach <PID>` - attach to some already running program

`core <PATH>` - analyse the coredump of some program that's finished running

`c/continue` 

`n/next`

`s/step` - one source line

`si/stepi` - one assembly intsruction

`b/break`

`r/run`

`start` - sets breakpoint at main, then runs it

`starti` - sets breakpoint at _start (assembly), then runs it

`info <registers/breakpoints/functions/many more...>`, just run info with no arguments to see all possible subcommands


