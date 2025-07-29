---
permalink: /misc/Memory
title: Memory
---

<br>

[Pointers in C / C++ - freeCodeCamp.org](https://www.youtube.com/watch?v=zuegQmMdy8M)

[Visualizing memory layout of Rust's data types - Sreekanth](https://www.youtube.com/watch?v=7_o-YRxf_cc)

[C Programming and Memory Management - Boot dev (TJ DeVries)](https://www.youtube.com/watch?v=rJrd2QMVbGM)



<br>



# Pointers

Pointers typically refer to virtual addresses

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

---
