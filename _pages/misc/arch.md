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
