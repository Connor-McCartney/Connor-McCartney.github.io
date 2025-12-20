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


The `VOID **ppvBits` (`void* BitmapMemory`) is the bitmap memory we receive from windows that we can draw to
