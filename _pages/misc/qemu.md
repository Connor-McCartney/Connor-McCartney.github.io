---
permalink: /misc/qemu
title: Configuring QEMU/Virt Manager
---

<br>

# Installation

<br>

```
sudo dnf install libvirt-daemon-driver-qemu.x86_64 qemu virt-manager virt-viewer dnsmasq bridge-utils libguestfs edk2-ovmf.noarch swtpm
sudo systemctl start libvirtd
sudo systemctl enable libvirtd
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

<br>

### Configurations

Change SATA Disk 1 to VirtIO Disk 1

Change NIC... to VirtIO

<br>

### Optional performance configurations

Click XML and then delete these lines:

```
    <timer name="rtc" tickpolicy="catchup"/>
    <timer name="pit" tickpolicy="delay"/>
```

Change `<timer name="hpet" present="no"/>` to `<timer name="hpet" present="yes"/>`

<br>

### Windows-specific configurations

I downloaded virtio-win-0.1.215.iso from here: <https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.215-2/>

Click +Add Hardware, select CDROM device to create 'SATA CDROM 2'

Browse > Browse local > and add the virtio-win-0.1.215.iso 

Add Hardware > TPM > type:emulated, Mode:CRB, Version:2.0

In Overview > Firmware choose one with OVMF, eg ....OVMF_CODE.secboot.fd (enabled secure boot)


<br>
<br>
<br>


Then we can click 'begin installation' 

Troubleshooting 'This PC doesn't meet the minimum system requirements to install this version of windows':

* Minimum 4GB RAM and 2 CPUs is required
* TPM and Secure-Boot are required (we will use swtpm - a TPM emulator)
* Minimum 64GB storage

Choose the w11 driver when partitioning.

Also, to continue without internet you may have to press Shift+F10 and then enter OOBE\BYPASSNRO

Network setup:

In E drive run the x64 driver. 

Unlock display settings:

<https://www.spice-space.org/download/windows/spice-guest-tools/spice-guest-tools-latest.exe>


<br>
<br>

# Creating Whonix VMs

<br>

<https://www.whonix.org/wiki/KVM>

<br>

```
cd Downloads
mkdir whonix
cd whonix
wget https://download.whonix.org/libvirt/16.0.5.3/Whonix-XFCE-16.0.5.3.Intel_AMD64.qcow2.libvirt.xz
tar -xvf Whonix*.libvirt.xz
touch WHONIX_BINARY_LICENSE_AGREEMENT_accepted
sudo virsh -c qemu:///system net-define Whonix_external*.xml
sudo virsh -c qemu:///system net-define Whonix_internal*.xml
sudo virsh -c qemu:///system net-autostart Whonix-External
sudo virsh -c qemu:///system net-start Whonix-External
sudo virsh -c qemu:///system net-autostart Whonix-Internal
sudo virsh -c qemu:///system net-start Whonix-Internal
sudo virsh -c qemu:///system define Whonix-Gateway*.xml
sudo virsh -c qemu:///system define Whonix-Workstation*.xml
sudo mv Whonix-Gateway*.qcow2 /var/lib/libvirt/images/Whonix-Gateway.qcow2
sudo mv Whonix-Workstation*.qcow2 /var/lib/libvirt/images/Whonix-Workstation.qcow2
cd ..
rm -rf whonix
```

You'll need to log into your Whonix-Gateway once and run

sudo setup-dist

in order to finalize the installation.

Tips:

* update with `upgrade-nonroot`
* CTRL+ALT to escape VM
* default password is `changeme`



<br>

<br>

<br>

# regular VMs

```
paru -S --noconfirm qemu-full virt-manager
```

```
Unable to connect to libvirt qemu:///system.
Verify that the 'libvirtd' daemon is running.
```

```
systemctl start libvirtd
```

```
Unable to connect to libvirt qemu:///system.

authentication unavailable: no polkit agent available to authenticate action 'org.libvirt.unix.manage'
```

```
sudo usermod -aG libvirt connor
```

```
Unable to complete install: 'Requested operation is not valid: network 'default' is not active'

Traceback (most recent call last):
...
  File "/usr/lib/python3.13/site-packages/libvirt.py", line 4594, in createXML
    raise libvirtError('virDomainCreateXML() failed')
libvirt.libvirtError: Requested operation is not valid: network 'default' is not active
```

```
paru -S --noconfirm bridge-utils dnsmasq
systemctl restart libvirtd
sudo virsh net-start default
```
