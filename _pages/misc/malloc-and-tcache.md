---
permalink: /misc/malloc-and-tcache
title: malloc and tcache
---

<br>

<br>


I'll focus on glibc ptmalloc on linux. 


<br>


<br>


There is an important distinction to be made between the *requested size*, the *usable size*, and the total *chunk size* of an allocation. 

<br>

When you call malloc, it will return some amount of memory greater than or equal to the requested size, for alignment/other reasons. This is the usable size. 

<br>

The usable size seems to be 24 at a minimum, otherwise the requested size rounded up to the next value such that it is equal to 8 modulo 16. 

<br>

The chunk size seems to be equal to the usable size + 8. But how can this be, if malloc uses 16 bytes of metadata?

<br>


The first 8 bytes of metadata is stored right before the usable memory, and contains the total chunk size of the current chunk (5 bits) and 3 internal flags (3 bits). This is included as part of the chunk. 

<br>

The other 8 bytes of metadata is stored right before the other metadata, and contains prev_size, the size of the prior chunk. This bleeds in to the previous chunk's usable memory, a clever optimisation. 



<br>


```

                                                                               |-------------------------------------------chunk B ---------------------------------------------|
                                                                               |                                                                                                |
                                                                               |                                                                                                |


|----------------------------------------- chunk A  ----------------------------------------------|
|                                                                                                 |
|                                                                                                 |


                     <------------------------chunk size------------------------------------------> 
 <-----8 bytes-----> <-------8 bytes-----> <------------------usable memory size------------------>                     <------------------usable memory size------------------> 
                                                                                <-----8 bytes-----> <------8 bytes----->                                     <-----8 bytes----->  
|-------------------|---------------------|--------------------------------------------------------|-------------------|--------------------------------------------------------|
|      chunk A      |      xxxxx AMP      |           usable memory            -      chunk B      |    xxxxx AMP      |           usable memory            -      chunk C      |
|     prev_size     |      size  flags    |                                    -     prev_size     |    size flags     |                                    -     prev_size     |
|-------------------|---------------------|--------------------------------------------------------|-------------------|--------------------------------------------------------|
                                                                                        ^                                                                            ^
                                                                           will contain size of chunk A                                                  will contain size of chunk B



 



```



<br>

```c
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

int main() {
    int requested_size = 25; 
    void *ptr = malloc(requested_size);

    size_t usable_size = malloc_usable_size(ptr);
    printf("Usable size: %zu bytes\n", usable_size);

    size_t chunk_size = usable_size + 8;
    printf("Chunk size: %zu bytes\n", chunk_size);

    size_t *header_ptr = (size_t *)((char *)ptr - 8);
    // The lower 3 bits of the size field are used for internal flags (A, M, P).
    chunk_size = *header_ptr & 0b11111000;
    printf("Chunk size read from metadata: %zu bytes\n", chunk_size);
    


    free(ptr);
    return 0;
}


```




<br>

<br>

<br>

Internal metadata flags: 
<br>

P (PREV_INUSE): Previous chunk is allocated (bit 0).

M (IS_MMAPPED): Chunk obtained via mmap (bit 1).

A (NON_MAIN_ARENA): Chunk belongs to a non-main thread arena (bit 2).



<br>


<br>


<br>

<br>


The tcache bin index is calculated using the chunk size:   `#define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)`

MINSIZE = 0x20

MALLOC_ALIGNMENT = 0x10

More cleanly: index = (chunk_size-1)/16. 

<br>





