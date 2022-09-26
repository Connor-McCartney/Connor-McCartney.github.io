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
sudo dnf install qemu virt-manager virt-viewer dnsmasq bridge-utils libguestfs edk2-ovmf.noarch
```

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

Windows 10 will be selected for Windows 11 - this is okay

Click XML and then delete these lines:

```
    <timer name="rtc" tickpolicy="catchup"/>
    <timer name="pit" tickpolicy="delay"/>
```

Change `<timer name="hpet" present="no"/>` to `<timer name="hpet" present="yes"/>`

Then apply (this will improve CPU useage).

Change SATA Disk 1 to VirtIO Disk 1

Change NIC... to VirtIO

<br>
<br>

Now some Windows-only drivers <https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.215-2/>:

I downloaded virtio-win-0.1.215.iso 

Click +Add Hardware, select CDROM device to create 'SATA CDROM 2'

Browse > Browse local > and add the virtio-win-0.1.215.iso 

Then we can click 'begin installation' :)


Troubleshooting 'This PC doesn't meet the minimum system requirements to install this version of windows':

* Minimum 4GB RAM and 2 CPUs is required
* TPM and Secure-Boot are required
* Minimum 64GB storage

We will use swtpm - a TPM emulator. 

```
sudo dnf install swtpm
```

Add Hardware > TPM > type:emulated, Mode:CRB, Version:2.0

In Overview > Firmware choose one with OVMF, eg ....OVMF_CODE.secboot.fd (enabled secure boot)


Once windows boots and it asks to look for drivers, I got an error with the w11 one but the w10 one seems to work. <br>
Also, to continue without internet you may have to pree Shift+F10 and then enter OOBE\BYPASSNRO

Network setup:

In E drive run the x64 driver. 

Unlock display settings:

<https://www.spice-space.org/download/windows/spice-guest-tools/spice-guest-tools-latest.exe>
