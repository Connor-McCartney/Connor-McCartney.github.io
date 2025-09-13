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

<br>

# x - examine

`x/<n><u><f> <address>`

u - unit size (b: 1 byte, h: 2 bytes, w: 4 bytes, g: 8 bytes)

f - format (d: decimal (signed), u: decimal (unsigned), x: hex, s: string, i: instructions, a: address)

n -  number of elements



<br>

<br>


# commands list

`disas/disass/disassemble`, also use `set disassembly-flavor intel` beforehand

`attach <PID>` - attach to some already running program

`core <PATH>` - analyse the coredump of some program that's finished running

`c/continue` 

`n/next` - one source line, but stepping over function calls

`ni/nexti` - one assembly intsruction, but stepping over function calls

`s/step` - one source line, but stepping into function calls

`si/stepi` - one assembly intsruction, but stepping into function calls

`b/break`, view with `info breakpoints`, delete with `del break <i>`

`r/run`

`start` - sets breakpoint at main, then runs it

`starti` - sets breakpoint at _start (assembly), then runs it

`info <registers/breakpoints/functions/many more...>`, just run info with no arguments to see all possible subcommands

`f/frame`

`p/print`

`display` - displays something automatically everytime it stops  <https://sourceware.org/gdb/current/onlinedocs/gdb#Auto-Display>

`set` - eg `set $my_var = ...`

`call`

`jump`

`finish` - runs until the current function returns
