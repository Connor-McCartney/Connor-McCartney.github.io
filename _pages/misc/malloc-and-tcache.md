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


The first 8 bytes of metadata contains the total chunk size of the current chunk (5 bits) and 3 internal flags (3 bits). 

<br>

