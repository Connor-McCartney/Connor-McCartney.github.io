

# Windows to Windows (RDP)

By default, RDP is disabled. Search 'Remote Desktop Settings' to enable it. You may need the pro editions of windows to enable it.

Use the 'ipconfig' command in powershell to get the IPv4 address.

Then enter this (or the PC name) in Remote Desktop Connection on the client to connect. 

If it doesn't work then a third-party firewall could be blocking it. <br>
I also learned that you can not RDP into your own computer haha.


# Linux to Windows (xfreerdp)

Usage: `xfreerdp /u:connor /p:password123 /v:xxx.xxx.xxx.xxx`

