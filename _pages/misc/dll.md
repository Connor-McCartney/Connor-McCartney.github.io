---
permalink: /misc/dll
title: Making a simple DLL
---


<br>

As much as I hate Windows, I'm bored so gonna try write a simple DLL. 


<br>


First, I installed Visual Studio Installer and blah blah get the MSVC compiler. 

<br>

I tried developer cmd and it was showing some PATH error so I deleted some stuff from path and that seemed to fix it. 

<br>

Now I can open developer powershell for windows and have access to cl command to compile. 

<br>



<br>






/LD tells the compiler to output a DLL instead of an exe


<br>


```c
#include <stdio.h>

__declspec(dllimport) int add(int a, int b);

int main() {
        int a = 6;
        int b = 7;

        int sum = add(a, b);

        printf("sum = %d\n", sum);
}
```


<br>

```c
#include <stdio.h>

// __declspec(dllexport) tells MSVC to make this function visible outside the DLL
__declspec(dllexport) int add(int a, int b) {
        return a + b;
}
```


<br>

You can compile with a .lib at compile time, or link at runtime using Explicit Linking (aka Dynamic Loading)


<br>

Compile time:

```
PS C:\Users\connor\Desktop> cat x.c
#include <stdio.h>

__declspec(dllimport) int add(int a, int b);

int main() {
        int a = 6;
        int b = 7;

        int sum = add(a, b);

        printf("sum = %d\n", sum);
}

PS C:\Users\connor\Desktop> cat connordll.c
#include <stdio.h>

// __declspec(dllexport) tells MSVC to make this function visible outside the DLL
__declspec(dllexport) int add(int a, int b) {
        return a + b;
}
PS C:\Users\connor\Desktop> cl /LD .\connordll.c
Microsoft (R) C/C++ Optimizing Compiler Version 19.51.36260 for x86
Copyright (C) Microsoft Corporation.  All rights reserved.

connordll.c
Microsoft (R) Incremental Linker Version 14.51.36260.0
Copyright (C) Microsoft Corporation.  All rights reserved.

/out:connordll.dll
/dll
/implib:connordll.lib
connordll.obj
   Creating library connordll.lib and object connordll.exp
PS C:\Users\connor\Desktop> cl x.c connordll.lib; .\x.exe
Microsoft (R) C/C++ Optimizing Compiler Version 19.51.36260 for x86
Copyright (C) Microsoft Corporation.  All rights reserved.

x.c
Microsoft (R) Incremental Linker Version 14.51.36260.0
Copyright (C) Microsoft Corporation.  All rights reserved.

/out:x.exe
x.obj
connordll.lib
sum = 13
PS C:\Users\connor\Desktop>

```



<br>


<br>


Runtime:


```c
#include <stdio.h>
#include <windows.h>

// define a function pointer type that matches the signature of "add"
typedef int (*AddFunc)(int, int);

int main() {
	HMODULE hDll = LoadLibraryA("connordll.dll"); // load the DLL
	AddFunc my_add_function = (AddFunc)GetProcAddress(hDll, "add"); // look up the memory address of the "add" function inside the loaded DLL
	int sum = my_add_function(6, 7); // call the function via the pointer
	printf("sum = %d\n", sum);
   	FreeLibrary(hDll); // unload when finished
}
```


<br>


```
PS C:\Users\connor\Desktop> cl x.c
Microsoft (R) C/C++ Optimizing Compiler Version 19.51.36260 for x86
Copyright (C) Microsoft Corporation.  All rights reserved.

x.c
Microsoft (R) Incremental Linker Version 14.51.36260.0
Copyright (C) Microsoft Corporation.  All rights reserved.

/out:x.exe
x.obj



PS C:\Users\connor\Desktop> .\x.exe
sum = 13
PS C:\Users\connor\Desktop>
```

<br>



