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

```rust
fn main() {
    let x: u8 = 10;
    let pointer: *const u8 = &x;
    println!("{}", x);                       // 10
    println!("{:p}", pointer);               // 0x7ffeb1f9b937
    unsafe {
        let dereferenced: u8 = *pointer;
        println!("{}", dereferenced);        // 10
    }
}
```

---
