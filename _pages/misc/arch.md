---
permalink: /misc/arch
title: Arch
---


<https://wiki.archlinux.org/title/installation_guide>


In the live environment systemd-timesyncd is enabled by default and time will be synced automatically once a connection to the internet is established.
<br>
(so no need to set time)


 
# BIOS with MBR

printf "o\nn\n\n\n\n+8G\nn\n\n\n\n\nt\n1\n82\na\n2\nw\n" | fdisk /dev/sda


# "Invalid or corrupted package (PGP signature)" fix

```bash
rm -rf /etc/pacman.d/gnupg
pacman-key --init
pacman-key --refresh
pacman-key --populate
sudo pacman -Sy archlinux-keyring
```
