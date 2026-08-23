---
permalink: /misc/htb/phantom-check
title: Phantom Check
---

<br>






<br>

<br>

<https://app.hackthebox.com/sherlocks/Operation%2520Blackout%25202025%253A%2520Phantom%2520Check?tab=play_sherlock>




<br>


<img width="661" height="140" alt="image" src="https://github.com/user-attachments/assets/413c22ff-5f3b-4251-b901-88773714378d" />



<br>



<br>


There is no machine, just a zip file to analyse. 



<br>


<br>




<img width="1405" height="400" alt="image" src="https://github.com/user-attachments/assets/0e0e79ab-9392-4075-9c91-bc04f0c688c7" />




<br>


<br>

<br>


Usually you just open .evtx files with Event Viewer on windows, but I'll test on the rust tool evtx_dump on linux. 


<br>


```
yay -S evtx
evtx_dump Windows-Powershell-Operational.evtx -o json > output.json
```



<br>




<br>



I made a janky parser that grabs the powershell payloads (includes outputs too)


```python
from json import loads
for line in open('output.json').read().splitlines()[1::2][::-1]:
    j = loads(line)["Event"]
    #print(j)
    #print('\n'*10)

    eventdata = j.get("EventData")
    if eventdata is not None:
        payload = eventdata.get("Payload")
        if payload is not None:
            print(f'payload: {payload}')

```



<br>


Scrolling through that we see


```
payload: CommandInvocation(Get-WmiObject): "Get-WmiObject"
ParameterBinding(Get-WmiObject): name="Class"; value="Win32_ComputerSystem"
CommandInvocation(Select-Object): "Select-Object"
ParameterBinding(Select-Object): name="ExpandProperty"; value="Model"
ParameterBinding(Select-Object): name="InputObject"; value="\\DESKTOP-M3AKJSD\root\cimv2:Win32_ComputerSystem.Name="DESKTOP-M3AKJSD""
```


<br>


So the answer to q1 is `Win32_ComputerSystem`


<br>


<br>

<br>

<br>



<img width="1383" height="188" alt="image" src="https://github.com/user-attachments/assets/3412e29b-a749-4c18-904f-00124e1a9780" />





<br>

<br>

<br>


I searched for 'Temperature' and found one result

```python
payload: CommandInvocation(Get-WmiObject): "Get-WmiObject"
ParameterBinding(Get-WmiObject): name="Query"; value="SELECT * FROM MSAcpi_ThermalZoneTemperature"
ParameterBinding(Get-WmiObject): name="ErrorAction"; value="SilentlyContinue"
NonTerminatingError(Get-WmiObject): "Invalid class "MSAcpi_ThermalZoneTemperature""
```


<br>

So the answer to q2 is `SELECT * FROM MSAcpi_ThermalZoneTemperature`


<br>

<br>

<br>


<img width="1385" height="185" alt="image" src="https://github.com/user-attachments/assets/e1175ae5-8880-43cc-b059-0dc9b9b3153f" />




<br>

<br>

<br>


I modified the prev parser


```python
from json import loads
for line in open('output.json').read().splitlines()[1::2][::-1]:
    j = loads(line)["Event"]
    #print(j)
    #print('\n'*10)

    eventdata = j.get("EventData")
    if eventdata is not None:
        scriptblocktext = eventdata.get("ScriptBlockText")
        if scriptblocktext is not None:
            print(f'scriptblocktext: {scriptblocktext}')

```



scroll through that and you can find 

```
scriptblocktext: function Check-VM
...
```




<br>

<br>

<br>


<img width="1367" height="174" alt="image" src="https://github.com/user-attachments/assets/255b0f0b-50bc-48f1-8f99-1f124571f1a3" />




<br>

<br>

<br>


Search for hklm or HKLM

the correct section is this:

```powershell
    if (!$hypervm)
        {
            $hyperv = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services
            if (($hyperv -match "vmicheartbeat") -or ($hyperv -match "vmicvss") -or ($hyperv -match "vmicshutdown") -or ($hyperv -match "vmiexchange"))
                {
                    $hypervm = $true
                }
        }

```


<br>

<br>

<br>



<img width="1390" height="184" alt="image" src="https://github.com/user-attachments/assets/bfd0104e-67a6-4d23-a7c4-894a7bfc74a6" />



<br>

<br>

<br>




```powershell
    #Virtual Box

    $vb = Get-Process
    if (($vb -eq "vboxservice.exe") -or ($vb -match "vboxtray.exe"))
        {
    
        $vbvm = $true
    
        }
```


<br>

<br>

Matching their requested format, answer to q5 is `vboxservice.exe, vboxtray.exe`


<br>


<br>

<br>




<img width="1380" height="193" alt="image" src="https://github.com/user-attachments/assets/c8223093-61d6-485e-93a1-f5ef5f638767" />



<br>


<br>


<br>





For this I used my first parser again. 


Search for 'This is a', and you can see the output log:

```
payload: CommandInvocation(Out-Default): "Out-Default"
ParameterBinding(Out-Default): name="InputObject"; value="This is a Hyper-V machine."
ParameterBinding(Out-Default): name="InputObject"; value="This is a VMWare machine."
```


<br>


So answer to q6 is `Hyper-V, VMWare`

<br>



