---
permalink: /misc/arch
title: Arch
---


<https://wiki.archlinux.org/title/installation_guide>


In the live environment systemd-timesyncd is enabled by default and time will be synced automatically once a connection to the internet is established.
<br>
(so no need to set time)


 
# "Invalid or corrupted package (PGP signature)" fix

```bash
sudo pacman -Sy pacman-keyring
```
