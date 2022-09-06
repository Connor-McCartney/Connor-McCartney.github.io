---
permalink: /misc/kde-plasma
title: KDE-Plasma
---


## Configure shortcuts (my preferences)

Quick tile window to the bottom: remove <br>
Quick tile window to the top: change to control + shift + up <br>
Show desktop grid: change to meta+tab <br>
Switch to next desktop: change to control+shift+right <br>
Switch to previous desktop: change to control+shift+left <br>


## Configure konsole

Open konsole<br>
Settings > Manage Profiles <br>
Create a new profile > Appearance > Choose a colour scheme <br>
Set this profile as default and apply<br>

Settings > Toolbars shown > disable

Toggle 'no border': alt f3

## Remove firefox

```
sudo dnf remove firefox 
rm -r ~/.mozilla 
rm -r ~/.cache/mozilla 
```
  
##  Remove krunner desktop 

Add the following to ~/.config/kdeglobals <br>

```
[KDE Action Restrictions][$i] 
run_command=false
```

## Disable screen locking/power saving

Advanced power settings > Stop charging only once below > 80% <br>
Energy saving > On AC Power > turn everything off except dim screen and energy saving <br>
Screen locking > disable

## Disable wallet

sudo dnf install kwalletmanager <br>
Then go to System Settings>Account Details>KDE Wallet and uncheck "Enable the KDE wallet subsystem"

## Grub Customizer

Disable look for other operating systems. <br>
Boot default entry after 1 second. <br>
Kernel parameters: quiet loglevel=1 nowatchdog nvme_load=YES fsck.mode=skip modprobe.blacklist=iTCO_wdt

## Desktop effects

Turn on wobbly windows, magic lamp, translucency, fall apart

## Fix monitor bug

Autostart > Add login script:

```
#!/bin/bash
killall plasmashell; sleep 3; plasmashell
```


## Forgetting wifi password

Go to your network connections. From there click on wireless tab. Choose your connection and then click the edit button. <br>
Make sure your password is entered then click on the wireless security tab. <br>
Then check the box in the bottom left corner that says available to all users. 
