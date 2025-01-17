---
permalink: /misc/Cheaderfiles
title: C header files
---

<br>


<br>

```c
#ifndef MYLIBRARY_H
#define MYLIBRARY_H

...

#endif
```

<br>

ifndef stands for if not defined. 

This setup (header guard) stops the same thing being defined multiple times, and avoids circular dependancies etc

`#pragma once` does the exact same thing

<br>

---

Imagine some file a.c

```c
#include <stdio.h>

int main() {
	int x = my_add(1, 2);
	printf("%d\n", x);
}
```

<br>

And you have my_add in b.c

```c
int my_add(int a, int b) {
	return a+b;
}
```

<br>

Now you must make a header file, b.h, and then you can compile them like this:

```
[~/Desktop] 
$ ls
a.c  b.c  b.h 

[~/Desktop] 
$ cat b.h 
#pragma once

// (add documentation here)
int my_add(int a, int b);

[~/Desktop] 
$ gcc a.c b.c

[~/Desktop] 
$ ./a.out 
3
```

Success :)

<br>

---

<br>

Now how about if b.c was closed source, but you had a .so file and header file?

I'll move b.c and b.h to a new folder, my_lib

and in a.c, rename `#include "b.h"` to `#include "my_lib/b.h"`

So now, `gcc a.c my_lib/b.c ` would succeed

But, now let's pretend b.c is closed source and we can't use it

<br>

```
[~/Desktop] 
$ gcc a.c -L $(pwd)/my_lib -l b
/usr/bin/ld: cannot find -lb: No such file or directory
collect2: error: ld returned 1 exit status
```

<br>

ld is giving us an error. 

you can debug with `ld --verbose`

```
$ ld -L $(pwd)/my_lib -l libb --verbose
<...SNIP...>

==================================================
ld: mode elf_x86_64
attempt to open /home/connor/Desktop/my_lib/libb.so failed
<...SNIP...>
```
