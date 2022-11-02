

# Windows to Windows (RDP)

By default, RDP is disabled. Search 'Remote Desktop Settings' to enable it.

Use the 'ipconfig' command in powershell to get the IPv4 address.

Then enter this (or the PC name) in Remote Desktop Connection on the client to connect. 

If it doesn't work then a third-party firewall could be blocking it. <br>
I also learned that you can not RDP into your own computer haha.


# Windows to Linux (XRDP)

<https://github.com/neutrinolabs/xrdp>

On the linux machine:

```
sudo dnf install xrdp ufw
sudo systemctl enable xrdp
sudo ufw allow from any to any port 3389 proto tcp
```

On the Windows machine:

Simply connect with the default Remote Desktop Connection tool.
