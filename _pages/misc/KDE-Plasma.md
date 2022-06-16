---
permalink: /misc/kde-plasma
title: KDE-Plasma
---


## Configure shortcuts (my preferences)

Open shortcuts

Delete the following:<br>
Quick tile window to the top <br>
Quick tile window to the bottom <br>

Change the following:<br>
If control+alt+t doesn't open terminal, click add application, search konsole and add shortcut. <br>
Show desktop grid: change to meta+tab <br>
Switch to next desktop: change to control+shift+right <br>
Switch to previous desktop: change to control+shift+left <br>


## Setup virtual desktops

Open virtual desktops <br>
I like to have 4. Turn navigation wraps around off. 


## Configure konsole

Open konsole<br>
Settings > Manage Profiles <br>
Create a new profile > Appearance > Choose a colour scheme <br>
Set this profile as default and apply<br>

Right click near top of konsole <br>
More actions > Configure special application settings <br>
Change exact match to substring match <br>
Add property > no titlebar and frame > yes > force <br>
Add property > maximised horizontally > yes > force <br>
Add property > maximised vertically > yes > force <br>

Settings > Toolbars shown > disable all
Settings > Show Menubar > disable


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

## Grub Customizer

Disable look for other operating systems. <br>
Boot default entry after 1 second. <br>
Kernel parameters: quiet loglevel=1 nowatchdog nvme_load=YES fsck.mode=skip modprobe.blacklist=iTCO_wdt

## Mirage global theme
<br>

## Desktop effects

Turn on wobbly windows, magic lamp, translucency, fall apart

## Fix monitor bug

Autostart > Add login script:

```
#!/bin/bash
killall plasmashell; sleep 3; plasmashell
```

## Disable wallet

sudo dnf install kwalletmanager <br>
Then go to System Settings>Account Details>KDE Wallet and uncheck "Enable the KDE wallet subsystem"


## Forgetting wifi password

Go to your network connections. From there click on wireless tab. Choose your connection and then click the edit button. <br>
Make sure your password is entered then click on the wireless security tab. <br>
Then check the box in the bottom left corner that says available to all users. 
