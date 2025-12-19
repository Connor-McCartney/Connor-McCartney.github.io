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
