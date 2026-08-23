

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

