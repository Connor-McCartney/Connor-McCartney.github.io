---
permalink: /misc/Memory
title: Memory
---

<br>

[Pointers in C / C++ - freeCodeCamp.org](https://www.youtube.com/watch?v=zuegQmMdy8M)

[Visualizing memory layout of Rust's data types - Sreekanth](https://www.youtube.com/watch?v=7_o-YRxf_cc)

[C Programming and Memory Management - Boot dev (TJ DeVries)](https://www.youtube.com/watch?v=rJrd2QMVbGM)

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


What's the difference between rust's 'regular' pointers and raw pointers? 

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

# 

<img width="859" height="962" alt="image" src="https://github.com/user-attachments/assets/20d8cb6f-93b5-4a21-83ca-df201a73cfc6" />


---
