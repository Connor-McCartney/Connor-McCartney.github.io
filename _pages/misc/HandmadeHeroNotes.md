# Handmade Hero Notes




<br>

<https://www.youtube.com/playlist?list=PL0PAV3gVZ9gmiTxKufnvxw2-WMFHTMX6c>


<br>


# Day 1 - setting up windows build


You can create a virtual drive to some folder, it'll also be visible from file explorer

```
subst w: C:\Users\crm36\Documents\handmadehero
cd w:
```



vcvarsall.exe sets environment variables in a cmd shell so that you can use cl (MSVC compiler, not clang)

I wanted to use powershell so I put this in $profile

```powershell
cmd /c '"C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 && set' |
  ForEach-Object {
    if ($_ -match '^(.*?)=(.*)$') {
      Set-Item -Path "Env:$($matches[1])" -Value $matches[2]
    }
  }
```

<br>


# Day 2 - Opening a Win32 Window


Creates simple window with CreateWindowEx, and makes a switch statement handling messages received by it.

PAINT message seems to be sent when it's created but also whenever it's resized. 

He says he uses static function variables when debugging but tries to avoid them in production. 


<br>

# Day 3 - Allocating a Backbuffer


"Since it's a 2D game and we want to render at probably fixed resolutions, eventually when the window is resized we'll probably only pick a size that corresponds to roughly how big the window is."


The `VOID **ppvBits` (`void* BitmapMemory`), from `CreateDIBSection`,  is the bitmap memory we receive from windows that we can draw to


<br>

48:09 

Option 1: right before you allocate a new DIBSection, free the old DIBSection

Option 2: wait and see if you can get the new one first, and if you can't, keep using the old one


<br>

# Day 4 - Animating the Backbuffer


HeapAlloc: Similar in spirit to malloc, gives you the exact amount of memory you request (sub-allocates out of pages).

VirtualAlloc: Lower level/more raw, allocates a certain (whole) number of memory pages. Eg if the page size is 4096 bytes, and you ask for less than that, it will still give you the entire page. 

There's also VirtualProtect, eg if someone else had a stale pointer to the page and tries to write to it you get a use-after-free. 

<br>

# Day 5 - Windows Graphics Review

just recap/refactoring

<br>

# Day 6 - Gamepad and Keyboard Input

xinput.h for controller input

A good example of loading dll's dynamically, and using stubs etc

Note that xinput does not support playstation controllers, my workaround was use the DS4Windows tool, it emulates an Xbox controller then no code changes are necessary


<br>

# Day 7 - Initializing DirectSound

windows makes sound such a pain...

<br>


# Day 8 - Writing a Square Wave to DirectSound

Handling circular buffer, locks etc

<br>

# Day 9 - Variable-Pitch Sine Wave Output

Mostly refactoring

<br>

# Day 10 - QueryPerformanceCounter and RDTSC


RDTSC - assembly instruction that counts CPU cycles

QueryPerformanceCounter - windows function that tries to measure wall (real) time as accurately as possible


<br>

# Day 11 - The Basics of Platform API Design


Thinking about how to code cross-platform support. 


Option 1: 

The old-fashioned way is a bunch of preprocessor stuff scattered everywhere like 

```c
#if LINUX
  ...
#elif WINDOWS
  ...
#elif MACOS
  ...
#endif
```

Not only is it pretty unreadable, but it also dictates the control flow must be the same across all platforms...


<br>

<br>

Option 2: 

'virtualise the operating system out to the game', calling from the game layer to the platform layer, a bunch of PlatformLayerDoThis(), PlatformLayerDoThat() functions

<br>

<br>

Option 3: 

The game layer is mostly providing services to the OS level, giving it the graphics/sound/user input/network IO/file IO. 

Have to isolate locations in the code where the platform layer wants services from the game, or the game wants services from the platform. 


<br>

# Day 12 - Platform-independent Sound Output


refactoring, still a bit janky



<br>

# Day 13 - Platform-independent User Input


refactoring

<br>

<br>

# Day 14 - Platform-independent Game Memory


allocate a big block of memory at the start and just use that throughout

<br>
