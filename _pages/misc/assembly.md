---
permalink: /misc/assembly
title: Assembly
---


<br>


There are many different assembly languages, depending on the CPU used. 

Intel and AMD commonly use the x86 architecture. 

32-bit CPUs commonly use x86 assembly. 

64-bit CPUs commonly use x86_64 assembly.

RISC and ARM assembly are other common ones.

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

```
.global _start
.intel_syntax noprefix

_start:
	mov 	rax, 60 # systemcall for exit
	syscall
```

Great, now let's check out choosing the exit code (note, they overflow if bigger than 256).

We can check the exit code of the previous program in bash with `echo $?`

Typically you should use exit code 0 to indicate the program ran successfuly. 

But for this example I'll try 7. 

<br>

```
[~/Desktop] 
$ cat x.s
.global _start
.intel_syntax noprefix

_start:
        mov     rax, 60 # system call for exit
        mov     rdi, 7  # exit code 7
        syscall

[~/Desktop] 
$ as x.s -o x.o && gcc -o x -nostdlib -static x.o

[~/Desktop] 
$ ./x

[~/Desktop] 
$ echo $?
7
```

<br>

# Addition

```
.global _start
.intel_syntax noprefix

_start:
	mov 	rax, 4
	add 	rax, 2
	# rax should now have 4+2=6

	mov 	rax, 60 
	mov 	rdi, 0 	
	syscall
```

<br>

You can observe the rax register with gdb

```
[~/Desktop] 
$ gdb
...

pwndbg> file x
Reading symbols from x...
(No debugging symbols found in x)

pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _start
0x0000000000402000  __bss_start
0x0000000000402000  _edata
0x0000000000402000  _end

pwndbg> break _start
Breakpoint 1 at 0x401000

pwndbg> r
Starting program: /home/connor/Desktop/x 

Breakpoint 1, 0x0000000000401000 in _start ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
[ REGISTERS / show-flags off / show-compact-regs off ]
 RAX  0
 RBX  0
 RCX  0
 RDX  0
 RDI  0
 RSI  0
 R8   0
 R9   0
 R10  0
 R11  0
 R12  0
 R13  0
 R14  0
 R15  0
 RBP  0
 RSP  0x7fffffffe4b0 ◂— 1
 RIP  0x401000 (_start) ◂— mov rax, 4
─────────[ DISASM / x86-64 / set emulate on ]─────────
 ► 0x401000 <_start>       mov    rax, 4                 RAX => 4
   0x401007 <_start+7>     add    rax, 2                 RAX => 6 (4 + 2)
   0x40100b <_start+11>    mov    rax, 0x3c              RAX => 0x3c
   0x401012 <_start+18>    mov    rdi, 0                 RDI => 0
   0x401019 <_start+25>    syscall  <SYS_exit>
   0x40101b                add    byte ptr [rax], al
   0x40101d                add    byte ptr [rax], al
   0x40101f                add    byte ptr [rax], al
   0x401021                add    byte ptr [rax], al
   0x401023                add    byte ptr [rax], al
   0x401025                add    byte ptr [rax], al
...
pwndbg> n
0x0000000000401007 in _start ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────
*RAX  4
 RBX  0
 RCX  0
 RDX  0
 RDI  0
 RSI  0
 R8   0
 R9   0
 R10  0
 R11  0
 R12  0
 R13  0
 R14  0
 R15  0
 RBP  0
 RSP  0x7fffffffe4b0 ◂— 1
*RIP  0x401007 (_start+7) ◂— add rax, 2
────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────
   0x401000 <_start>       mov    rax, 4                 RAX => 4
 ► 0x401007 <_start+7>     add    rax, 2                 RAX => 6 (4 + 2)
   0x40100b <_start+11>    mov    rax, 0x3c              RAX => 0x3c
   0x401012 <_start+18>    mov    rdi, 0                 RDI => 0
   0x401019 <_start+25>    syscall  <SYS_exit>
   0x40101b                add    byte ptr [rax], al
   0x40101d                add    byte ptr [rax], al
   0x40101f                add    byte ptr [rax], al
   0x401021                add    byte ptr [rax], al
   0x401023                add    byte ptr [rax], al
   0x401025                add    byte ptr [rax], al
...
pwndbg> n
0x000000000040100b in _start ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────
*RAX  6
 RBX  0
 RCX  0
 RDX  0
 RDI  0
 RSI  0
 R8   0
 R9   0
 R10  0
 R11  0
 R12  0
 R13  0
 R14  0
 R15  0
 RBP  0
 RSP  0x7fffffffe4b0 ◂— 1
*RIP  0x40100b (_start+11) ◂— mov rax, 0x3c
────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────
   0x401000 <_start>       mov    rax, 4                 RAX => 4
   0x401007 <_start+7>     add    rax, 2                 RAX => 6 (4 + 2)
 ► 0x40100b <_start+11>    mov    rax, 0x3c              RAX => 0x3c
   0x401012 <_start+18>    mov    rdi, 0                 RDI => 0
   0x401019 <_start+25>    syscall  <SYS_exit>
   0x40101b                add    byte ptr [rax], al
   0x40101d                add    byte ptr [rax], al
   0x40101f                add    byte ptr [rax], al
   0x401021                add    byte ptr [rax], al
   0x401023                add    byte ptr [rax], al
   0x401025                add    byte ptr [rax], al
...
pwndbg> 
```

<br>

# assembly in bootloader that draws to VGA video mode

I thought this was pretty cool

<https://www.youtube.com/watch?v=M-RVBiAmXj0>

```python
ORG 0x7C00

start:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00

    mov al, 0x13
    int 0x10

    mov edi, 0xA0000
    mov byte [edi], COLOR_RED 

    jmp $

begin_draw dd 0
sq_width dd 40
sq_height dd 70
DRAW_START equ 0xA0000
COLOR_RED equ 0x04

times 510 - ($-$$) db 0
dw 0xAA55
```

`nasm x.asm && q x`

<br>


---


<br>

Actually, I'll start using NASM too, because that's what's used in this book <https://www.amazon.com/Low-Level-Programming-Assembly-Execution-Architecture/dp/1484224027>

# Hello World

