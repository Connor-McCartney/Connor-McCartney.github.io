






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



I made a janky parser that grabs the powershell payload


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




