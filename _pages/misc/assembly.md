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

# fuction stack frames


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


<br>

<br>

<br>


Now let's look at something with some more functions. 


```c
int mult(int a, int b) {
    int ret = a * b;
    return ret;
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
pwndbg> disas main
Dump of assembler code for function main:
   0x0000000000001154 <+0>:	    push   rbp
   0x0000000000001155 <+1>:	    mov    rbp,rsp
   0x0000000000001158 <+4>:	    mov    edi,0x5
   0x000000000000115d <+9>:	    call   0x1132 <triple>
   0x0000000000001162 <+14>:	mov    eax,0x0
   0x0000000000001167 <+19>:	pop    rbp
   0x0000000000001168 <+20>:	ret
End of assembler dump.
pwndbg> disas triple
Dump of assembler code for function triple:
   0x0000000000001132 <+0>:	    push   rbp
   0x0000000000001133 <+1>:	    mov    rbp,rsp
   0x0000000000001136 <+4>:	    sub    rsp,0x18
   0x000000000000113a <+8>:	    mov    DWORD PTR [rbp-0x14],edi
   0x000000000000113d <+11>:	mov    eax,DWORD PTR [rbp-0x14]
   0x0000000000001140 <+14>:	mov    esi,0x3
   0x0000000000001145 <+19>:	mov    edi,eax
   0x0000000000001147 <+21>:	call   0x1119 <mult>
   0x000000000000114c <+26>:	mov    DWORD PTR [rbp-0x4],eax
   0x000000000000114f <+29>:	mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000001152 <+32>:	leave
   0x0000000000001153 <+33>:	ret
End of assembler dump.
pwndbg> disas mult
Dump of assembler code for function mult:
   0x0000000000001119 <+0>:	    push   rbp
   0x000000000000111a <+1>:	    mov    rbp,rsp
   0x000000000000111d <+4>:	    mov    DWORD PTR [rbp-0x14],edi
   0x0000000000001120 <+7>:	    mov    DWORD PTR [rbp-0x18],esi
   0x0000000000001123 <+10>:	mov    eax,DWORD PTR [rbp-0x14]
   0x0000000000001126 <+13>:	imul   eax,DWORD PTR [rbp-0x18]
   0x000000000000112a <+17>:	mov    DWORD PTR [rbp-0x4],eax
   0x000000000000112d <+20>:	mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000001130 <+23>:	pop    rbp
   0x0000000000001131 <+24>:	ret
End of assembler dump.
```


Main:

```asm
push   rbp                # save base pointer from whatever initially calls main
mov    rbp,rsp            # main's stack frame
mov    edi,0x5            # argument to triple
call   0x1132 <triple>    # call triple
mov    eax,0x0            # main's return code
pop    rbp                # restore base pointer to return to whatever initially called main
ret                       # return
```

If I break right at *main, I see:

```
RBP = 0x7fffffffe6d0 —▸ 0x7fffffffe730 ◂— 0
RSP = 0x7fffffffe638 —▸ 0x7ffff7c27675 ◂— mov edi, eax   (instruction right after main returns?)
```


Then after executing 

```asm
push   rbp                
mov    rbp,rsp
# note here there's usually some 'sub rsp, ...' to actually allocate the stack size, but well in this code main doesn't need to store anything on the stack there aren't any variables etc so it's just empty like a sub rsp, 0
```

we have set up main's stack frame. 

```
RBP = 0x7fffffffe630 
RSP = 0x7fffffffe630 
```

stack:

```
0x7fffffffe630:	0x00007fffffffe6d0 (previous base pointer to whatever called main)             <- rbp, rsp
...
```




<br>

<br>


Let's keep going, `mov    edi,0x5` does nothing, but `call  triple` is going to implicitly do some stuff. 

call will always 'essentially' do this:

```asm
sub     rsp, 8
mov     [rsp], return_address
jmp     target
```

```
RBP = 0x7fffffffe630                                               (base pointer of main, which called triple)
RSP = 0x7fffffffe628 —▸ 0x555555555162 (main+14) ◂— mov eax, 0     (the instruction in main immediately after call triple)
```

Stack:

```
0x7fffffffe630:	0x00007fffffffe6d0 (previous base pointer to whatever called main)             <- rbp
0x7fffffffe628:	0x0000555555555162 (the instruction in main immediately after call triple)     <- rsp
...
```

Next is this to finish setting up triple's stack frame

```asm
push   rbp
mov    rbp, rsp
sub    rsp, 24      (24 bytes allocated for triple's stack frame)
```

Stack:

```
0x7fffffffe630:	0x00007fffffffe6d0 (previous base pointer to whatever called main)           
0x7fffffffe628:	0x0000555555555162 (the instruction in main immediately after call triple)     
0x7fffffffe620:	0x00007fffffffe630 (base pointer of main, saved when calling triple)          <- rbp
0x7fffffffe618:	0x0000000000000000
0x7fffffffe610:	0x0000000000000000
0x7fffffffe608:	0x0000000000000000                                                            <- rsp
...
```


<br>

<br>

A full look at the rest of triple:

```asm
# x = rdi
mov    DWORD PTR [rbp-0x14],edi   
mov    eax,DWORD PTR [rbp-0x14]

mov    esi,0x3                    # rsi = 3
mov    edi,eax                    # rdi = x
call   0x555555555119 <mult>      # calling convention is mul(rdi, rsi)

# ret = rax
mov    DWORD PTR [rbp-0x4],eax
mov    eax,DWORD PTR [rbp-0x4]  

leave                             # cleans up triple's stack frame before returning, equivalent to mov rsp, rbp (restore stack pointer) and then pop rbp (restore base pointer)
ret
```

Now let's continue:

```
mov    DWORD PTR [rbp-0x14],edi   
mov    eax,DWORD PTR [rbp-0x14]
mov    esi,0x3              
mov    edi,eax             
```

rsp and rbp haven't changed, stack now looks like this (just the 5 is new):

```
0x7fffffffe630:	0x00007fffffffe6d0 (previous base pointer to whatever called main)           
0x7fffffffe628:	0x0000555555555162 (the instruction in main immediately after call triple)     
0x7fffffffe620:	0x00007fffffffe630 (base pointer of main, saved when calling triple)          <- rbp
0x7fffffffe618:	0x0000000000000000
0x7fffffffe610:	0x0000000000000000
0x7fffffffe608:	0x0000000500000000                                                            <- rsp
```



<br>

<br>

Next we call ret mult. 

Remember call will 'essentially' do this:

```asm
sub     rsp, 8
mov     [rsp], return_address
jmp     target
```

```
 RBP  0x7fffffffe620 —▸ 0x7fffffffe630 —▸ 0x7fffffffe6d0 —▸ 0x7fffffffe730 ◂— 0
*RSP  0x7fffffffe600 —▸ 0x55555555514c (triple+26) ◂— mov dword ptr [rbp - 4], eax
```

Stack:

```
0x7fffffffe630:	0x00007fffffffe6d0 (previous base pointer to whatever called main)           
0x7fffffffe628:	0x0000555555555162 (the instruction in main immediately after call triple)     
0x7fffffffe620:	0x00007fffffffe630 (base pointer of main, saved when calling triple)           <- rbp
0x7fffffffe618:	0x0000000000000000
0x7fffffffe610:	0x0000000000000000
0x7fffffffe608:	0x0000000500000000                                                            
0x7fffffffe600:	0x000055555555514c (the instruction in triple immediately after calling mult)  <- rsp
...
```

Finish setting up mult's stack frame (although like main there is no sub rsp, ..., but for a different reason you'll see below :) ):

```
push   rbp
mov    rbp,rsp
```


Stack:

```
0x7fffffffe630:	0x00007fffffffe6d0 (previous base pointer to whatever called main)           
0x7fffffffe628:	0x0000555555555162 (the instruction in main immediately after call triple)     
0x7fffffffe620:	0x00007fffffffe630 (base pointer of main, saved when calling triple)          
0x7fffffffe618:	0x0000000000000000
0x7fffffffe610:	0x0000000000000000
0x7fffffffe608:	0x0000000500000000                                                            
0x7fffffffe600:	0x000055555555514c (the instruction in triple immediately after calling mult)  
0x7fffffffe5f8: 0x00007fffffffe620 (base pointer of triple, saved when calling mult)           <- rbp, rsp
...
```



<br>

<br>

You may note that mult does not subtract from rsp! why I wondered?????

After some research, it turns out there is a 128-byte 'red zone', which can be used safely as long as the function doesn't call any other functions! A neat little optimisation that's always done, even with -O0. 

<https://stackoverflow.com/questions/38042188/where-exactly-is-the-red-zone-on-x86-64>

<https://en.wikipedia.org/wiki/Red_zone_(computing)>



<br>

<br>


A full look at the rest of mult:

```asm
# mul(rdi, rsi)  a is rdi, b is rsi
mov    DWORD PTR [rbp-0x14],edi  # a = rdi
mov    DWORD PTR [rbp-0x18],esi  # b = rsi
mov    eax,DWORD PTR [rbp-0x14]  # tmp = a 
imul   eax,DWORD PTR [rbp-0x18]  # tmp *= b

# ret = tmp
mov    DWORD PTR [rbp-0x4],eax 
mov    eax,DWORD PTR [rbp-0x4]

pop    rbp
ret
```

```c
int mult(int a, int b) {
    int ret = a * b;
    return ret;
}
```

Let's continue. None of these instructions should affect rsp or rbp. But there's some local variables in the red zone of the stack. 

```asm
mov    DWORD PTR [rbp-0x14],edi  
mov    DWORD PTR [rbp-0x18],esi 
mov    eax,DWORD PTR [rbp-0x14]  
imul   eax,DWORD PTR [rbp-0x18]  
mov    DWORD PTR [rbp-0x4],eax 
mov    eax,DWORD PTR [rbp-0x4]
```

Stack:

```asm
0x7fffffffe630:	0x00007fffffffe6d0 (previous base pointer to whatever called main)           
0x7fffffffe628:	0x0000555555555162 (the instruction in main immediately after call triple)     
0x7fffffffe620:	0x00007fffffffe630 (base pointer of main, saved when calling triple)          
0x7fffffffe618:	0x0000000000000000
0x7fffffffe610:	0x0000000000000000
0x7fffffffe608:	0x0000000500000000                                                            
0x7fffffffe600:	0x000055555555514c (the instruction in triple immediately after calling mult)  
0x7fffffffe5f8: 0x00007fffffffe620 (base pointer of triple, saved when calling mult)           <- rbp, rsp
--- red zone below ---
0x7fffffffe5f0:	0x0000000f00000000  (ret = 15)
0x7fffffffe5e8:	0x0000000000000000
0x7fffffffe5e0:	0x0000000500000003  (a=5 and b=3)
...
```


<br>

Next is `pop    rbp`. 

So this takes the value at the 'top' of the stack (where rsp is), 0x00007fffffffe620, and puts it into rbp. 

Essentially setting it up for the next ret instruction, cause 0x00007fffffffe620 is the base pointer of triple which called mult. 

Pop will also always add 8 to rsp. 

Stack:

```asm
0x7fffffffe630:	0x00007fffffffe6d0 (previous base pointer to whatever called main)           
0x7fffffffe628:	0x0000555555555162 (the instruction in main immediately after call triple)     
0x7fffffffe620:	0x00007fffffffe630 (base pointer of main, saved when calling triple)           <- rbp
0x7fffffffe618:	0x0000000000000000
0x7fffffffe610:	0x0000000000000000
0x7fffffffe608:	0x0000000500000000                                                            
0x7fffffffe600:	0x000055555555514c (the instruction in triple immediately after calling mult)  <- rsp
0x7fffffffe5f8: old popped junk       
...
```


<br>

<br>


Next is `ret`

Implicitly it will kinda do `pop rip`, returning back to the next instruction in triple immediately after calling mult. 

And again the pop implicitly adds 8 to rsp. 

```
 RBP  0x7fffffffe620 —▸ 0x7fffffffe630 —▸ 0x7fffffffe6d0 —▸ 0x7fffffffe730 ◂— 0
*RSP  0x7fffffffe608 ◂— 0x500000000
*RIP  0x55555555514c (triple+26) ◂— mov dword ptr [rbp - 4], eax
```

Stack:

```asm
0x7fffffffe630:	0x00007fffffffe6d0 (previous base pointer to whatever called main)           
0x7fffffffe628:	0x0000555555555162 (the instruction in main immediately after call triple)     
0x7fffffffe620:	0x00007fffffffe630 (base pointer of main, saved when calling triple)           <- rbp
0x7fffffffe618:	0x0000000000000000
0x7fffffffe610:	0x0000000000000000
0x7fffffffe608:	0x0000000500000000                                                             <- rsp                                           
0x7fffffffe600:	old popped junk
0x7fffffffe5f8: old popped junk       
...
```


<br>

<br>


Now we have returned back to triple. 

Next is this so step twice:

```
# ret = rax
mov    DWORD PTR [rbp-0x4],eax
mov    eax,DWORD PTR [rbp-0x4]
```

Stack (only 0x7fffffffe618 changed, which has rax returned by mult):

```asm
0x7fffffffe630:	0x00007fffffffe6d0 (previous base pointer to whatever called main)           
0x7fffffffe628:	0x0000555555555162 (the instruction in main immediately after call triple)     
0x7fffffffe620:	0x00007fffffffe630 (base pointer of main, saved when calling triple)           <- rbp
0x7fffffffe618:	0x0000000f00000000 (ret = 15)
0x7fffffffe610:	0x0000000000000000
0x7fffffffe608:	0x0000000500000000                                                             <- rsp                                           
0x7fffffffe600:	old popped junk
0x7fffffffe5f8: old popped junk       
...
```



<br>

<br>

And now we arrive at the `leave` instruction. 

You can see it implicitly clears/pops all the 24 bytes allocated at the start, and then also does a `pop rbp`


Stack:

```asm
0x7fffffffe630:	0x00007fffffffe6d0 (previous base pointer to whatever called main)            <- rbp
0x7fffffffe628:	0x0000555555555162 (the instruction in main immediately after call triple)    <- rsp
0x7fffffffe620:	old popped junk
0x7fffffffe618:	old popped junk
0x7fffffffe610:	old popped junk
0x7fffffffe608:	old popped junk                                      
0x7fffffffe600:	old popped junk
0x7fffffffe5f8: old popped junk       
...
```

<br>

<br>


Nex it `ret`, which remember is kinda like `pop rip`

Stack:

```asm
0x7fffffffe630:	0x00007fffffffe6d0 (previous base pointer to whatever called main)            <- rbp, rsp
0x7fffffffe628:	old popped junk
0x7fffffffe620:	old popped junk
0x7fffffffe618:	old popped junk
0x7fffffffe610:	old popped junk
0x7fffffffe608:	old popped junk                                      
0x7fffffffe600:	old popped junk
0x7fffffffe5f8: old popped junk       
...
```


<br>

Now we are back in main. 

And if we execute the rest of main then 0x7fffffffe630 gets popped too. 


```asm
0x7fffffffe630:	old popped junk
0x7fffffffe628:	old popped junk
0x7fffffffe620:	old popped junk
0x7fffffffe618:	old popped junk
0x7fffffffe610:	old popped junk
0x7fffffffe608:	old popped junk                                      
0x7fffffffe600:	old popped junk
0x7fffffffe5f8: old popped junk       
...
```



<br>


# small arrays

There will be some threshold, it could depends on lots of things I think, the compiler, optimisation level, machine architecture, etc. 

For me it was 32 elements * 8 bytes per element = 256 bytes. 

<= 32 elements will do individual mov's

eg

```c
int main() {
    long my_list[32] = {0xa0ea132a134ab585, 0x8989cef66ebfa45c, 0x0774a7e04c852a56, 0x73e0f28de99282b3, 0x88165aff92a45b5c, 0x61fcd6729de1bb3b, 0x72cf46c7f74ae700, 0x80b2f200841b42cd, 0xdf374c1064969103, 0x17ec045959b91f97, 0xd8991e9b771a7246, 0x006c7d8f8783ac93, 0x2105e92dfcc83f8b, 0x8b41ab5772b432a5, 0x5bf6da1b85402bcb, 0x7763fad3d0bfbe9d, 0x4317f367188618a3, 0x508c627dccea5a92, 0x5522325731b5ac35, 0xa10b3f70cba8c125, 0x399df0803ed3d5bc, 0xe91cc4906f648c3d, 0xfafef0acca375b7d, 0xf0d430c203eb9bc2, 0xfd223a24398d786b, 0x71a182c71b23339c, 0x1a0d12c7906671c1, 0x8e9d27004cc624df, 0x2e36326df69e1603, 0xaf655da066e45254, 0x6033b28ebfb41ee1, 0x90d8b4593ba9bb88};
}
```

```
$ gcc y.c -o y -fno-stack-protector; gdb y
pwndbg> disas main
Dump of assembler code for function main:
   0x0000000000001119 <+0>:	    push   rbp
   0x000000000000111a <+1>:	    mov    rbp,rsp
   0x000000000000111d <+4>:	    sub    rsp,0x88
   0x0000000000001124 <+11>:	movabs rax,0xa0ea132a134ab585
   0x000000000000112e <+21>:	mov    QWORD PTR [rbp-0x100],rax
   0x0000000000001135 <+28>:	movabs rax,0x8989cef66ebfa45c
   0x000000000000113f <+38>:	mov    QWORD PTR [rbp-0xf8],rax
   0x0000000000001146 <+45>:	movabs rax,0x774a7e04c852a56
   0x0000000000001150 <+55>:	mov    QWORD PTR [rbp-0xf0],rax
   0x0000000000001157 <+62>:	movabs rax,0x73e0f28de99282b3
   0x0000000000001161 <+72>:	mov    QWORD PTR [rbp-0xe8],rax
   0x0000000000001168 <+79>:	movabs rax,0x88165aff92a45b5c
   0x0000000000001172 <+89>:	mov    QWORD PTR [rbp-0xe0],rax
   0x0000000000001179 <+96>:	movabs rax,0x61fcd6729de1bb3b
   0x0000000000001183 <+106>:	mov    QWORD PTR [rbp-0xd8],rax
   0x000000000000118a <+113>:	movabs rax,0x72cf46c7f74ae700
   0x0000000000001194 <+123>:	mov    QWORD PTR [rbp-0xd0],rax
   0x000000000000119b <+130>:	movabs rax,0x80b2f200841b42cd
   0x00000000000011a5 <+140>:	mov    QWORD PTR [rbp-0xc8],rax
   0x00000000000011ac <+147>:	movabs rax,0xdf374c1064969103
   0x00000000000011b6 <+157>:	mov    QWORD PTR [rbp-0xc0],rax
   0x00000000000011bd <+164>:	movabs rax,0x17ec045959b91f97
   0x00000000000011c7 <+174>:	mov    QWORD PTR [rbp-0xb8],rax
   0x00000000000011ce <+181>:	movabs rax,0xd8991e9b771a7246
   0x00000000000011d8 <+191>:	mov    QWORD PTR [rbp-0xb0],rax
   0x00000000000011df <+198>:	movabs rax,0x6c7d8f8783ac93
   0x00000000000011e9 <+208>:	mov    QWORD PTR [rbp-0xa8],rax
   0x00000000000011f0 <+215>:	movabs rax,0x2105e92dfcc83f8b
   0x00000000000011fa <+225>:	mov    QWORD PTR [rbp-0xa0],rax
   0x0000000000001201 <+232>:	movabs rax,0x8b41ab5772b432a5
   0x000000000000120b <+242>:	mov    QWORD PTR [rbp-0x98],rax
   0x0000000000001212 <+249>:	movabs rax,0x5bf6da1b85402bcb
   0x000000000000121c <+259>:	mov    QWORD PTR [rbp-0x90],rax
   0x0000000000001223 <+266>:	movabs rax,0x7763fad3d0bfbe9d
   0x000000000000122d <+276>:	mov    QWORD PTR [rbp-0x88],rax
   0x0000000000001234 <+283>:	movabs rax,0x4317f367188618a3
   0x000000000000123e <+293>:	mov    QWORD PTR [rbp-0x80],rax
   0x0000000000001242 <+297>:	movabs rax,0x508c627dccea5a92
   0x000000000000124c <+307>:	mov    QWORD PTR [rbp-0x78],rax
   0x0000000000001250 <+311>:	movabs rax,0x5522325731b5ac35
   0x000000000000125a <+321>:	mov    QWORD PTR [rbp-0x70],rax
   0x000000000000125e <+325>:	movabs rax,0xa10b3f70cba8c125
   0x0000000000001268 <+335>:	mov    QWORD PTR [rbp-0x68],rax
   0x000000000000126c <+339>:	movabs rax,0x399df0803ed3d5bc
   0x0000000000001276 <+349>:	mov    QWORD PTR [rbp-0x60],rax
   0x000000000000127a <+353>:	movabs rax,0xe91cc4906f648c3d
   0x0000000000001284 <+363>:	mov    QWORD PTR [rbp-0x58],rax
   0x0000000000001288 <+367>:	movabs rax,0xfafef0acca375b7d
   0x0000000000001292 <+377>:	mov    QWORD PTR [rbp-0x50],rax
   0x0000000000001296 <+381>:	movabs rax,0xf0d430c203eb9bc2
   0x00000000000012a0 <+391>:	mov    QWORD PTR [rbp-0x48],rax
   0x00000000000012a4 <+395>:	movabs rax,0xfd223a24398d786b
   0x00000000000012ae <+405>:	mov    QWORD PTR [rbp-0x40],rax
   0x00000000000012b2 <+409>:	movabs rax,0x71a182c71b23339c
   0x00000000000012bc <+419>:	mov    QWORD PTR [rbp-0x38],rax
   0x00000000000012c0 <+423>:	movabs rax,0x1a0d12c7906671c1
   0x00000000000012ca <+433>:	mov    QWORD PTR [rbp-0x30],rax
   0x00000000000012ce <+437>:	movabs rax,0x8e9d27004cc624df
   0x00000000000012d8 <+447>:	mov    QWORD PTR [rbp-0x28],rax
   0x00000000000012dc <+451>:	movabs rax,0x2e36326df69e1603
   0x00000000000012e6 <+461>:	mov    QWORD PTR [rbp-0x20],rax
   0x00000000000012ea <+465>:	movabs rax,0xaf655da066e45254
   0x00000000000012f4 <+475>:	mov    QWORD PTR [rbp-0x18],rax
   0x00000000000012f8 <+479>:	movabs rax,0x6033b28ebfb41ee1
   0x0000000000001302 <+489>:	mov    QWORD PTR [rbp-0x10],rax
   0x0000000000001306 <+493>:	movabs rax,0x90d8b4593ba9bb88
   0x0000000000001310 <+503>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000000000001314 <+507>:	mov    eax,0x0
   0x0000000000001319 <+512>:	leave
   0x000000000000131a <+513>:	ret
End of assembler dump.
```


Note the sub rsp,0x88, which is 136 bytes. 

The array will eat into the red zone (128 bytes) so only another 128 bytes is needed to be allocated as the stack frame, rather than 256. 

Then an extra 8 bytes I presume for stack allignment. 

so 128+8 = 136



# big arrays

Now I'll show a 33 element one, which will have more than 256 bytes. 

There are no more individual mov's. 

```c
int main() {
    long my_list[33] = {0xdfa85653b8bf5ab7, 0xaa43138ceac13504, 0x73eedc4fe80b50d7, 0x3cfa4687bb1ca78a, 0xc22acd68104be153, 0x65dddff568e23a92, 0x8a50268201e5e33a, 0x7a2f8010e1bec750, 0x8b4cdbe70dee8d8c, 0x3f236ed9937edc08, 0xe4ebb800c63d7ddc, 0x4c75de6f34375d43, 0x211807eff3da1173, 0x9f23ae23044585e5, 0x7f8f718008171996, 0xdecb9c2d55e2a4af, 0x577ea761c77881c0, 0x342c5a943e2eccd2, 0x64016b46d7e67821, 0x5c2b0f12610987c9, 0x410a42cf94341054, 0xc20bf80d33baffbe, 0x6f7597d5cebc0e85, 0x6ecb9adda4afc993, 0xecbaf721e30b66a7, 0x0f95f4bfe4e032a7, 0xa5d590f5137c482a, 0xb60dcef80f26b847, 0xc5f3ad64183f3231, 0xbbf444878689bfbc, 0x25037d4586ff2adb, 0xf6a34861910e4554, 0xb4d1a674a823abd4};
}
```

```
pwndbg> disas main
Dump of assembler code for function main:
   0x0000000000001119 <+0>:	    push   rbp
   0x000000000000111a <+1>:	    mov    rbp,rsp
   0x000000000000111d <+4>:	    sub    rsp,0x98
   0x0000000000001124 <+11>:	lea    rax,[rbp-0x110]
   0x000000000000112b <+18>:	lea    rdx,[rip+0xeee]        # 0x2020
   0x0000000000001132 <+25>:	mov    ecx,0x21
   0x0000000000001137 <+30>:	mov    rdi,rax
   0x000000000000113a <+33>:	mov    rsi,rdx
   0x000000000000113d <+36>:	rep movs QWORD PTR es:[rdi],QWORD PTR ds:[rsi]
   0x0000000000001140 <+39>:	mov    eax,0x0
   0x0000000000001145 <+44>:	leave
   0x0000000000001146 <+45>:	ret
End of assembler dump.
```

