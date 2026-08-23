

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




<br>



