---
permalink: /misc/arch
title: Arch
---


<https://wiki.archlinux.org/title/installation_guide>


# "Invalid or corrupted package (PGP signature)" fix

```bash
rm -rf /etc/pacman.d/gnupg
pacman-key --init
pacman-key --refresh
pacman-key --populate
sudo pacman -Sy archlinux-keyring
```

# Installing python packages

```bash
pip install --break-system-packages ...
```


# In kde6 show desktop grid has been scrapped in favour of 'Toggle Grid View'

<https://bbs.archlinux.org/viewtopic.php?id=293656>
