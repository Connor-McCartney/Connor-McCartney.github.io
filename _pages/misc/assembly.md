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
	mov 	rax, 60 # systemcall for exit (linux)
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

```
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

```
ORG 0x7C00

start:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00

    mov al, 0x13
    int 0x10

    call draw_square

    jmp $

draw_square:
    mov edi, DRAW_START
    mov eax, [sq_y]
    mov ebx, 320
    mul ebx
    add eax, edi
    mov edi, eax
    add edi, [sq_x]

    jmp .put_pixel

.setup:

.move_down:
    add edi, 320
    sub edi, [sq_width]
    xor ecx, ecx

.put_pixel:
    mov byte [edi], COLOR_RED
    inc edi
    inc ecx
    cmp ecx, [sq_width]
    jl .put_pixel

    inc edx
    cmp edx, [sq_height]
    jl .move_down


sq_x dd 10
sq_y dd 10
begin_draw dd 0
sq_width dd 320 - 10
sq_height dd 200 - 10
DRAW_START equ 0xA0000 ;+ 64000
COLOR_RED equ 0x04

times 510 - ($-$$) db 0
dw 0xAA55
```


<br>

<https://mendelson.org/wpdos/videomodes.txt>

<br>


TempleOS uses 640x480 resolution, 16-color (mode 0x12 / 12H, the highest resolution supported by standard VGA)

<br>



---


<br>

Actually, I'll start using NASM too, because that's what's used in this book <https://www.amazon.com/Low-Level-Programming-Assembly-Execution-Architecture/dp/1484224027>


<br>

![image](https://github.com/user-attachments/assets/1a9cf889-03df-4c25-8b66-537046c86615)

<br>

![image](https://github.com/user-attachments/assets/736d8109-dfcd-45f4-886e-eadc163d66e4)

<br>

<https://math.hws.edu/eck/cs220/f22/registers.html>


# Hello World

```
global _start

;section .data
message: db "hello, world!", 10 ; the 10 is ord('\n')
;len: equ $-message


;section .text
_start:
    mov rax, 1 ; syscall for write (on linux)
    mov rdi, 1 ; stdout
    mov rsi, message ; string address
    mov rdx, 14 ; string len
    syscall

    ; exit
    mov rax, 60 
    mov rdi, 0  
    syscall
```

```
$ nasm -f elf64 x.asm && ld x.o && ./a.out
hello, world!
```

<br>

<br>


# base 10 to hex

```python
codes =  "0123456789ABCDEF"

def convet_to_hex(n):
    rcx = 64 # total bits
    while True:
        rax = n
        rcx -= 4
        rax >>= rcx

        print(codes[rax % 16])

        if rcx == 0:
            break

convet_to_hex(0x1122334455667788)
```

<br>

```
global _start

codes:
    db "1123456789ABCDEF"


section .text
_start:
    mov rax, 0x1122334455667788

    mov rdi, 1 ; write to stdout
    mov rdx, 1 ; string lens, always 1 at a time
    mov rcx, 64 ;  0x1122334455667788 has 64 bits

.loop:
    push rax ; save rax before our loop

    sub rcx, 4    ; rcx -= 4
    sar rax, cl   ;  Shift Arithmetic Right,     rcx errors so u have to use cl (lowest 8 bits)
    and rax, 0xf  ; 15 (will perform mod 16)

    lea rsi, [codes + rax] ; string address
    mov rax, 1 ; write syscall

    push rcx
    syscall ; the write syscall will affect rcx so you have to save and restore with push and pop
    pop rcx

    pop rax ; restore rax after our loop

    test rcx, rcx ; TEST sets the zero flag, ZF, if they're equal (bitwise &) 
    jnz .loop   ; jump if not zero (checks the zero flag)  (so break loop when rcx is 0)




    mov rax, 60; exit
    xor rdi, rdi
    syscall
```


<br>


# Looking at the stack

The stack might look something like

```
...
0x7fffffffe878 ... other stuff before your program executes
0x7fffffffe870 ... other stuff before your program executes
0x7fffffffe868 ... other stuff before your program executes
--- program starts
0x7fffffffe860 ... junk
0x7fffffffe858 ... junk
0x7fffffffe850 ... junk
0x7fffffffe848 ... junk
...
0x000000000000 ... junk
```

RBP (base pointer) is typically 0 initially

in this example, RSP is 0x7fffffffe860 initially

now suppose we push some stuff on the stack:

```
global _start

_start:
    push 90
    push 100
    push 110


    ;exit
    mov rdi, 0
    mov rax,60
    syscall
```

Everytime we push something, RSP will decrease by 8 bytes, and the value will be stored there.

The maximum register values is 2**64, which is 8 bytes, which is why it's in 8-byte sections (although the stack should usually be 16-byte alligned for various other reasons...)

If ur getting stack allignment errors when calling function, you can subtract 8 from the rsp and then add it back after. 

<https://stackoverflow.com/questions/64729055/what-does-aligning-the-stack-mean-in-assembly>

<https://stackoverflow.com/questions/51070716/glibc-scanf-segmentation-faults-when-called-from-a-function-that-doesnt-align-r>

```
$ gdb ./a.out 
pwndbg> break _start
Breakpoint 1 at 0x401000
pwndbg> r
Starting program: /home/connor/t/a.out 

Breakpoint 1, 0x0000000000401000 in _start ()
...
 RSP  0x7fffffffe860 ◂— 1
 RIP  0x401000 (_start) ◂— push 0x5a
─────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────
 ► 0x401000 <_start>       push   0x5a
   0x401002 <_start+2>     push   0x64
   0x401004 <_start+4>     push   0x6e
   0x401006 <_start+6>     mov    edi, 0                 EDI => 0
   0x40100b <_start+11>    mov    eax, 0x3c              EAX => 0x3c
   0x401010 <_start+16>    syscall  <SYS_exit>
   0x401012                add    byte ptr [rax], al
   0x401014                add    byte ptr [rax], al
   0x401016                add    byte ptr [rax], al
   0x401018                add    byte ptr [rax], al
   0x40101a                add    byte ptr [rax], al
──────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffe860 ◂— 1
01:0008│     0x7fffffffe868 —▸ 0x7fffffffeb5b ◂— '/home/connor/t/a.out'
02:0010│     0x7fffffffe870 ◂— 0
03:0018│     0x7fffffffe878 —▸ 0x7fffffffeb70 ◂— 'SHELL=/bin/bash'

pwndbg> n
...

*RSP  0x7fffffffe858 ◂— 0x5a /* 'Z' */
*RIP  0x401002 (_start+2) ◂— push 0x64
─────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────
   0x401000 <_start>       push   0x5a
 ► 0x401002 <_start+2>     push   0x64
   0x401004 <_start+4>     push   0x6e
   0x401006 <_start+6>     mov    edi, 0                 EDI => 0
   0x40100b <_start+11>    mov    eax, 0x3c              EAX => 0x3c
   0x401010 <_start+16>    syscall  <SYS_exit>
   0x401012                add    byte ptr [rax], al
   0x401014                add    byte ptr [rax], al
   0x401016                add    byte ptr [rax], al
   0x401018                add    byte ptr [rax], al
   0x40101a                add    byte ptr [rax], al
──────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffe858 ◂— 0x5a /* 'Z' */
01:0008│     0x7fffffffe860 ◂— 1
02:0010│     0x7fffffffe868 —▸ 0x7fffffffeb5b ◂— '/home/connor/t/a.out'
03:0018│     0x7fffffffe870 ◂— 0
04:0020│     0x7fffffffe878 —▸ 0x7fffffffeb70 ◂— 'SHELL=/bin/bash'

pwndbg> n
...

*RSP  0x7fffffffe850 ◂— 0x64 /* 'd' */
*RIP  0x401004 (_start+4) ◂— push 0x6e
─────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────
   0x401000 <_start>       push   0x5a
   0x401002 <_start+2>     push   0x64
 ► 0x401004 <_start+4>     push   0x6e
   0x401006 <_start+6>     mov    edi, 0                 EDI => 0
   0x40100b <_start+11>    mov    eax, 0x3c              EAX => 0x3c
   0x401010 <_start+16>    syscall  <SYS_exit>
   0x401012                add    byte ptr [rax], al
   0x401014                add    byte ptr [rax], al
   0x401016                add    byte ptr [rax], al
   0x401018                add    byte ptr [rax], al
   0x40101a                add    byte ptr [rax], al
──────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffe850 ◂— 0x64 /* 'd' */
01:0008│     0x7fffffffe858 ◂— 0x5a /* 'Z' */
02:0010│     0x7fffffffe860 ◂— 1
03:0018│     0x7fffffffe868 —▸ 0x7fffffffeb5b ◂— '/home/connor/t/a.out'
04:0020│     0x7fffffffe870 ◂— 0
05:0028│     0x7fffffffe878 —▸ 0x7fffffffeb70 ◂— 'SHELL=/bin/bash'

pwndbg> n
...

*RSP  0x7fffffffe848 ◂— 0x6e /* 'n' */
*RIP  0x401006 (_start+6) ◂— mov edi, 0
─────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────
   0x401000 <_start>       push   0x5a
   0x401002 <_start+2>     push   0x64
   0x401004 <_start+4>     push   0x6e
 ► 0x401006 <_start+6>     mov    edi, 0                 EDI => 0
   0x40100b <_start+11>    mov    eax, 0x3c              EAX => 0x3c
   0x401010 <_start+16>    syscall  <SYS_exit>
   0x401012                add    byte ptr [rax], al
   0x401014                add    byte ptr [rax], al
   0x401016                add    byte ptr [rax], al
   0x401018                add    byte ptr [rax], al
   0x40101a                add    byte ptr [rax], al
──────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffe848 ◂— 0x6e /* 'n' */
01:0008│     0x7fffffffe850 ◂— 0x64 /* 'd' */
02:0010│     0x7fffffffe858 ◂— 0x5a /* 'Z' */
03:0018│     0x7fffffffe860 ◂— 1
04:0020│     0x7fffffffe868 —▸ 0x7fffffffeb5b ◂— '/home/connor/t/a.out'
05:0028│     0x7fffffffe870 ◂— 0
```

```
--- program starts
0x7fffffffe860 ... 1
0x7fffffffe858 ... junk
0x7fffffffe850 ... junk
0x7fffffffe848 ... junk
```

```
--- program starts
0x7fffffffe860 ... 1
0x7fffffffe858 ... 90
0x7fffffffe850 ... junk
0x7fffffffe848 ... junk
```

```
--- program starts
0x7fffffffe860 ... 1
0x7fffffffe858 ... 90
0x7fffffffe850 ... 100
0x7fffffffe848 ... junk
```

```
--- program starts
0x7fffffffe860 ... 1
0x7fffffffe858 ... 90
0x7fffffffe850 ... 100
0x7fffffffe848 ... 110
```


<br>

<br>

# what is db doing?


```
message: db "hey", 10
```

db defines a variable of type bytes. 

Alternatively, you can do this:

```python
>>> int.from_bytes(b'hey\n', 'little')
175727976
```

```
global _start

_start:
    push 175727976
    mov rsi, rsp ; string pointer

    mov rax, 1 ; syscall for write (on linux)
    mov rdi, 1 ; stdout
    mov rdx, 4 ; string len
    syscall

    ; exit
    mov rax, 60 
    mov rdi, 0  
    syscall
```

<br>

<br>

# what is lea doing?

I think of it as syntactic sugar for indexing bytes. 

instead of 

```
_start:
    push 175727976

    mov rsi, rsp
    add rsi, 1

    mov rax, 1 ; syscall for write (on linux)
    mov rdi, 1 ; stdout
    mov rdx, 3 ; string len
    syscall
```

you can just do 

```
_start:
    push 175727976

    lea rsi, [rsp+1] 

    mov rax, 1 ; syscall for write (on linux)
    mov rdi, 1 ; stdout
    mov rdx, 3 ; string len
    syscall
```

<br>

<br>


# Allocating memory (buffer/array)



<br>

option 1: use some builtin


<br>

option 2: decrease rsp (push does this automatically)



<br>

option 3: move the base pointer (kinda better practice than the stack pointer)

<https://stackoverflow.com/questions/13468991/how-do-i-use-a-buffer-in-an-assembly-procedure>


<br>










# Calling convention

<https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI>

<img width="493" height="209" alt="image" src="https://github.com/user-attachments/assets/f84059d0-4083-4151-8f57-29792f0f8d73" />










<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

---

# disassembling some actual c code


```
[~/t]
$ cat x.c
int main() {}

[~/t]
$ gcc x.c

[~/t]
$ gdb a.out
pwndbg> disas main
Dump of assembler code for function main:
   0x0000000000001119 <+0>:	    push   rbp
   0x000000000000111a <+1>:	    mov    rbp,rsp
   0x000000000000111d <+4>:	    mov    eax,0x0
   0x0000000000001122 <+9>:	    pop    rbp
   0x0000000000001123 <+10>:	ret
End of assembler dump.
```

Here's a totally empty program, the `mov eax,0x0` is main's return code, and everything else is creating and destroying the main function's stack frame. 


Now let's look at something with some more functions. 


```c
int mult(int a, int b) {
    int ret = a * b;
    return a * b;
}

int triple(int x) {
    int ret = mult(x, 3);
    return ret;
}

int main() {
    triple(5);
}
```

<br>

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000001000  _init
0x0000000000001020  _start
0x0000000000001119  mult
0x0000000000001136  triple
0x0000000000001158  main
0x0000000000001170  _fini
pwndbg> disas main
Dump of assembler code for function main:
   0x0000000000001158 <+0>:	push   rbp
   0x0000000000001159 <+1>:	mov    rbp,rsp
   0x000000000000115c <+4>:	mov    edi,0x5
   0x0000000000001161 <+9>:	call   0x1136 <triple>
   0x0000000000001166 <+14>:	mov    eax,0x0
   0x000000000000116b <+19>:	pop    rbp
   0x000000000000116c <+20>:	ret
End of assembler dump.
pwndbg> disas mult
Dump of assembler code for function mult:
   0x0000000000001119 <+0>:	push   rbp
   0x000000000000111a <+1>:	mov    rbp,rsp
   0x000000000000111d <+4>:	mov    DWORD PTR [rbp-0x14],edi
   0x0000000000001120 <+7>:	mov    DWORD PTR [rbp-0x18],esi
   0x0000000000001123 <+10>:	mov    eax,DWORD PTR [rbp-0x14]
   0x0000000000001126 <+13>:	imul   eax,DWORD PTR [rbp-0x18]
   0x000000000000112a <+17>:	mov    DWORD PTR [rbp-0x4],eax
   0x000000000000112d <+20>:	mov    eax,DWORD PTR [rbp-0x14]
   0x0000000000001130 <+23>:	imul   eax,DWORD PTR [rbp-0x18]
   0x0000000000001134 <+27>:	pop    rbp
   0x0000000000001135 <+28>:	ret
End of assembler dump.
pwndbg> disas triple
Dump of assembler code for function triple:
   0x0000000000001136 <+0>:	push   rbp
   0x0000000000001137 <+1>:	mov    rbp,rsp
   0x000000000000113a <+4>:	sub    rsp,0x18
   0x000000000000113e <+8>:	mov    DWORD PTR [rbp-0x14],edi
   0x0000000000001141 <+11>:	mov    eax,DWORD PTR [rbp-0x14]
   0x0000000000001144 <+14>:	mov    esi,0x3
   0x0000000000001149 <+19>:	mov    edi,eax
   0x000000000000114b <+21>:	call   0x1119 <mult>
   0x0000000000001150 <+26>:	mov    DWORD PTR [rbp-0x4],eax
   0x0000000000001153 <+29>:	mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000001156 <+32>:	leave
   0x0000000000001157 <+33>:	ret
End of assembler dump.
```


Main:

```asm
push   rbp                # save base pointer from whatever initially calls main
mov    rbp,rsp            # main's stack frame
mov    edi,0x5            # argument to triple
call   0x1136 <triple>    # call triple
mov    eax,0x0            # main's return code
pop    rbp                # restore base pointer to return to whatever initially called main
ret                       # return
```

If I break right at *main, I see:

```
RBP = 0x7fffffffe6d0 —▸ 0x7fffffffe730 ◂— 0
RSP = 0x7fffffffe638 —▸ 0x7ffff7c27675 ◂— mov edi, eax   (instruction right after main returns in _start)
```


Then after executing 

```asm
push   rbp                
mov    rbp,rsp            
```

we have set up main's stack frame. 

```
RBP = 0x7fffffffe630 
RSP = 0x7fffffffe630 
```

