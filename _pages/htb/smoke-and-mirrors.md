

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
scriptblocktext: prompt
scriptblocktext: cls
scriptblocktext: prompt
scriptblocktext: Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableIntrusionPreventionSystem $true
scriptblocktext: prompt
scriptblocktext: cls
scriptblocktext: prompt
scriptblocktext: prompt
...
```



<br>

<br>





