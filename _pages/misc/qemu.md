---
permalink: /misc/qemu
title: Configuring QEMU/Virt Manager
---

<br>

This guide will be using fedora.

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
