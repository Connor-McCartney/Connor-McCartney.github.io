---
permalink: /misc/Cheaderfiles
title: C header files
---

<br>


<br>

```
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

