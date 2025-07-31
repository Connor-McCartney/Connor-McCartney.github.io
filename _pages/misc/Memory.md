---
permalink: /misc/Memory
title: Memory
---

<br>

[Pointers in C / C++ - freeCodeCamp.org](https://www.youtube.com/watch?v=zuegQmMdy8M)

[Visualizing memory layout of Rust's data types - Sreekanth](https://www.youtube.com/watch?v=7_o-YRxf_cc)

[C Programming and Memory Management - Boot dev (TJ DeVries)](https://www.youtube.com/watch?v=rJrd2QMVbGM)

<https://www.youtube.com/watch?v=MIL2BK02X8A>


<br>

<https://softwareengineering.stackexchange.com/questions/325704/how-is-stack-and-heap-are-assigned-to-each-processes>

<https://softwareengineering.stackexchange.com/questions/386511/does-each-process-have-its-own-section-of-data-text-stack-and-heap-in-the-me>

<https://stackoverflow.com/questions/79923/what-and-where-are-the-stack-and-heap>

<https://icarus.cs.weber.edu/~dab/cs1410/textbook/4.Pointers/memory.html>

<https://en.wikipedia.org/wiki/Virtual_memory>

<https://www.cs.miami.edu/home/burt/learning/Csc521.101/notes/virtual-memory-notes.html>

<br>



# Pointers

Pointers typically refer to virtual addresses (either on the stack or the heap)

c:

```c
#include <stdio.h>

int main() {
    int n = 10;
    int* pointer = &n;
    int dereferenced = *pointer;
    printf("%p\n", pointer);       // 0x7fff46413d08
    printf("%ld\n", pointer);      // 140734372068616
    printf("%d\n", dereferenced);  // 10
}
```

<br>

rust raw pointer: 

```rust
fn main() {
    let x: u8 = 10;
    let raw_pointer: *const u8 = &x;
    println!("{}", x);                           // 10
    println!("{:p}", raw_pointer);               // 0x7ffc85bdfd77
    unsafe {
        let dereferenced: u8 = *raw_pointer;
        println!("{}", dereferenced);            // 10
    }
}
```

<br>


rust 'regular' pointer: 

```rust
fn main() {
    let x: u8 = 10;
    let pointer = &x;
    println!("{}", x);                       // 10
    println!("{:p}", pointer);            
    let dereferenced: u8 = *pointer;         // 0x7ffdf9b46647
    println!("{}", dereferenced);            // 10
}
```

<br>

# What's the difference between rust's 'regular' pointers and raw pointers? 

They both contain the same address. 

By default, the type is some reference &T. In the above example, it would be &u8  (`let pointer: &u8 = &x;`)

The main difference is just whether or not they're subject to all of rust's safety checks (ownership, lifetimes, concurrency etc)

<br>

# why do they all seem to start with 0x7f...... ?

on 64-bit CPUs, we only use 48 bits for memory addressing purposes, and out of this, 

only 47 bits are used for userspace memory. 

```python
>>> hex(2**47-1)
'0x7fffffffffff'
```

The stack starts somewhere around this maximum and then grows downwards. 

<br>

# How big are pointers?

Typically 8 bytes (64 bits) on 64-bit architectures. 

```c
#include <stdint.h>
#include <stdio.h>
int main() {
    int n = 123;
    printf("%lu\n", sizeof(&n));        // 8 bytes
    printf("%lu\n", sizeof(int*));      // 8 bytes
    printf("%lu\n", sizeof(intptr_t));  // 8 bytes
    printf("%lu\n", sizeof(uintptr_t)); // 8 bytes
}
```

<br>

# How big is each address unit?

The unit of addressability in almost all modern CPU architectures (x86, x86-64, ARM, etc.) is 1 byte (8 bits).

Data types larger than 1 byte are groups of consecutive addresses.

For example, an int is 4 bytes. 

```c
int main() {
    int x = 0x11223344;
}
```

If we pass it into gdb, we see:

```
[~/t]
$ cat x.c
int main() {
    int x = 0x11223344;
}

[~/t]
$ gcc x.c

[~/t]
$ gdb a.out
...
pwndbg> b main
Breakpoint 1 at 0x111d
pwndbg> r
...
pwndbg> n
...
b+ 0x55555555511d <main+4>                        mov    dword ptr [rbp - 4], 0x11223344     [0x7fffffffe65c] <= 0x11223344
...

pwndbg> x 0x7fffffffe65c
0x7fffffffe65c:	0x11223344

pwndbg> x/b 0x7fffffffe65c
0x7fffffffe65c:	0x44
pwndbg> x/b 0x7fffffffe65d
0x7fffffffe65d:	0x33
pwndbg> x/b 0x7fffffffe65e
0x7fffffffe65e:	0x22
pwndbg> x/b 0x7fffffffe65f
0x7fffffffe65f:	0x11
pwndbg>
```

<br>

# Can you dereference a void pointer?

No! You must cast it first

You can't do pointer arithmetic on void pointers either (add/subtract)

<br>

# Pointer arithmetic

If you add 1 to a pointer, it doesn't actually add 1, it adds 1 * the size of the data type. 

To actually add 1, that's where the intptr_t or uintptr_t type becomes useful.

Eg:

```c
#include <stdio.h>
#include <stdint.h>

int main() {
    int x = 0x11223344;
    int* ptr = &x;

    printf("%ld\n", sizeof(int));           // 4

    printf("%ld\n", (long) ptr);            // 140727286628548
    printf("%ld\n", (long) (ptr+1));        // 140727286628552 (+4)

    intptr_t intptr = (intptr_t) ptr;      
    printf("%ld\n", intptr);                // 140727286628548
    printf("%ld\n", intptr+1);              // 140727286628549 (+1)



    printf("%x\n", x);                        // 11223344
    printf("%x\n", *ptr);                     // 11223344 
    printf("%x\n", *((int8_t*) (intptr+0)));  // 44   
    printf("%x\n", *((int8_t*) (intptr+1)));  // 33   
    printf("%x\n", *((int8_t*) (intptr+2)));  // 22
    printf("%x\n", *((int8_t*) (intptr+3)));  // 11
}
```

<br>

# A bizzare trick: `arr[i]` = `i[arr]` 🤯

```c
#include <stdio.h>

int main() {
    int arr[] = {11, 22, 33, 44, 55};

    for (int i=0; i<5; i++) {
        printf("%d\n", arr[i]);
    }

    printf("\n");

    //int* p = &(arr[0]);
    int* p = arr;
    for (int i=0; i<5; i++) {
        printf("%d\n", *(p+i));
    }

    printf("\n");

    for (int i=0; i<5; i++) {
        printf("%d\n", i[arr]); // i[arr] = *(i+arr) = *(arr+i) = arr[i]
    }
}
```

<br>

# Arrays as function arguments

You must also pass the length of the array as another argument, because within the new function there's no way to get the length. 

(Strings are an exception/avoid this by using a null terminator)

(Rust is different, you don't have to)


<br>

# String initialisation

This works as expected:

```c
#include <stdio.h>

int main() {
    char mystr[] = "hello";   // string gets stored on the stack, as a character array
    mystr[0] = 'x';
    printf("%s\n", mystr);
}
```

<br>

But beware initialising like this:

```c
#include <stdio.h>

int main() {
    char* mystr = "hello"; // gets stored as a compile time constant, probably in .text 
    mystr[0] = 'x';  // segfault! can't modify constant
    printf("%s\n", mystr);
}
```

<br>


# Pointer as function return type example

```c
#include <stdio.h>
#include <stdlib.h>

int* add(int* a, int* b) {
    int* s = (int*) malloc(sizeof(int));
    *s = *a + *b; 
    return s;
}

int main() {
    int a = 1;
    int b = 2;
    int* sum = add(&a, &b);
    printf("%d\n", *sum);
    free(sum);
}
```

<br>

# function pointers

```c
#include <stdio.h>

int add(int a, int b) {
    return a+b;
}

int mul(int a, int b) {
    return a*b;
}

int calc(int (*op)(int, int), int a, int b) {
    return op(a, b);
}

int main() {
    //int (*add_function_ptr)(int, int) = add;
    //int (*mul_function_ptr)(int, int) = mul;
    printf("%d\n", calc(add, 6, 2));
    printf("%d\n", calc(mul, 6, 2));
}
```

<br>


























<br>

# Where are the stack and heap physically stored?

In RAM/swap

<br>

# Virtual memory

An operating system with virtual memory will provide each process with its own virtual address space.

You can check process id's with `ps -a` and check their memory mappings with eg `cat /proc/892/maps`

<img width="859" height="962" alt="image" src="https://github.com/user-attachments/assets/20d8cb6f-93b5-4a21-83ca-df201a73cfc6" />


<br>

<br>

The above image shows a rough/example of ELF64 segments. In reality there are more segments than just the .bss, .data and .text shown. 

The text segment is also known as the code segment. It is read-only. 

The data segment contains initialised static variables. They can be modified. 

The bss segment stands for block start by symbol. 


<br>

# What happens in multi-threaded applications?

While it is one process, they have different threads. 

Each thread has it's own stack, but all the threads share the heap. As you may know, this is how race conditions can occur and why locking etc is needed. 

<br>

# How long does stack/heap memory last?

Heap memory must be manually allocated and exists until manually deallocated. 

'Stack frames' are sections of the stack dedicated to a particular function call. 

When the function exits, the stack pointer is restored to its previous value, effectively "freeing" the stack memory used by the function.


<br>

# base address for PIE executables

```c
#include <stdio.h>
#include <stdlib.h>
int main() {
    for (int i=0; i<10; i++) {
        void* my_memory = malloc(1);
        printf("%p\n", my_memory);
    }
}
```

```
[~/t]
$ gcc x.c && ./a.out
0x55cacf56e2a0
0x55cacf56e6d0
0x55cacf56e6f0
0x55cacf56e710
0x55cacf56e730

[~/t]
$ gcc x.c && ./a.out
0x56524d7282a0
0x56524d7286d0
0x56524d7286f0
0x56524d728710
0x56524d728730
```

If you run it many times you'll see 0x55... and 0x56... 

(note if you compile with -no-pie then the range is way bigger)

Where is this defined? Of course ASLR randomizes it but let's look for a rough base. 

In <https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/elf.h> there is:

```c
/*
 * This is the base location for PIE (ET_DYN with INTERP) loads. On
 * 64-bit, this is above 4GB to leave the entire 32-bit address
 * space open for things that want to use the area for 32-bit pointers.
 */
#define ELF_ET_DYN_BASE		(mmap_is_ia32() ? 0x000400000UL : \
						  (DEFAULT_MAP_WINDOW / 3 * 2))
```

Where is `DEFAULT_MAP_WINDOW` defined? <https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/page_64_types.h>

```c
#define DEFAULT_MAP_WINDOW	((1UL << 47) - PAGE_SIZE)
```

and Linux's page size is 4096 bytes. Finally we can calculate ELF_ET_DYN_BASE as:

```python
>>> hex(2*(2**47 - 4096)//3)
'0x555555554aaa'
```


<br>

# stack size on linux

You can check with `ulimit -a`, the default stack size is 8 MiB. 

If you use more than than you get a stackoverflow and the kernel terminates the process. 

<br>

# How to analyse a binary's section headers?

`readelf -S a.out`

These include .text .data and .bss

<br>


---
