---
permalink: /misc/assembly
title: Assembly
---


<br>


There are many different assembly languages, depending on the CPU used. 

Intel and AMD commonly use the x86 architecture. 

32-bit CPUs commonly use x86 assembly. 

64-bit CPUs commonly use x86_64 assembly.

ARM assembly is another common one.

I'll just focus on x86_64. 

There are also many compilers, such as NASM and GAS. 

I'll use the GNU assembler (GAS, executable named 'as').

GCC actually automatically invokes GAS when compiling c code. 

<br>

# BARE PROGRAM

```
[~/Desktop] 
$ cat x.s
.global _start

_start:

[~/Desktop] 
$ as x.s -o x.o && gcc -o x -nostdlib -static x.o

[~/Desktop] 
$ ./x
Segmentation fault (core dumped)
```

<br>

It segfaults because there's no exit syscall, so let's make that. 

```asm
.global _start
.intel_syntax noprefix

_start:
	mov 	rax, 60 # systemcall for exit
	syscall
```
