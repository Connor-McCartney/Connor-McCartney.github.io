---
permalink: /misc/qemu
title: Configuring QEMU/Virt Manager
---

<br>

# Installation

<br>

```
sudo dnf install libvirt-daemon-driver-qemu.x86_64
sudo systemctl start libvirtd
sudo systemctl enable libvirtd
```

```
sudo dnf install qemu virt-manager virt-viewer dnsmasq bridge-utils libguestfs
```

* vde2 missing https://github.com/virtualsquare/vde-2/blob/master/INSTALL

```
sudo vim /etc/libvirt/libvirtd.conf
```

Uncomment the following:

```
unix_sock_group = "libvirt"
unix_sock_ro_perms = "0777"
unix_sock_rw_perms = "0770"
```

```
sudo usermod -aG libvirt connor
```

reboot the machine now, then continue

```
sudo systemctl restart libvirtd
```

<br>

# Creating VMs

<br>

I'm going to install Windows 11. 

Grab the iso here: <https://www.microsoft.com/software-download/windows11>

Edit > Preferences > General > Enable XML Editing (to be able to make advanced configurations)

Click 'create a new VM' then follow the prompts until 'customize configuration before install'
