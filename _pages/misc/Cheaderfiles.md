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

Imageine some file a.c

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
a.c  b.c  b.h  tmp

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
