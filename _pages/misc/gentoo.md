

<https://wiki.gentoo.org/wiki/Handbook:AMD64#Installing_Gentoo>

You can do it from any live linux iso.

First become root.

```bash
fdisk -l
```

Figure out what disk the computer uses (not the USB!) eg /dev/sda
Partition for UEFI:

```bash
fdisk /dev/sda
g

# boot
n
1
default
+256M
t
1

# swap
n
2
default
+16G
t
2
19

# root
n
3
default
default

w
```


```bash
mkfs.vfat -F 32 /dev/sda1
mkfs.ext4 /dev/sda3
mkswap /dev/sda2
swapon /dev/sda2
mkdir --parents /mnt/gentoo
mount /dev/sda3 /mnt/gentoo
```


Set datetime, MMDDhhmm  eg 120810302022  is 8th December 10:30 am 2022

```bash
date 120810302022
```

Download the openrc stage3 from here: <https://www.gentoo.org/downloads/>

```bash
cd /mnt/gentoo
wget https://bouncer.gentoo.org/fetch/root/all/releases/amd64/autobuilds/20221205T133149Z/stage3-amd64-openrc-20221205T133149Z.tar.xz

tar xpvf stage3-*.tar.xz --xattrs-include='*.*' --numeric-owner
rm -rf stage3-*.tar.xz
```


A good choice for MAKEOPTS is the smaller of the number of threads the CPU has, or the total amount of system RAM divided by 2 GiB.
Mirrors can be found here <https://www.gentoo.org/downloads/mirrors/>

```bash
vim /mnt/gentoo/etc/portage/make.conf
```

```bash
COMMON_FLAGS="-march=native -O2 -pipe"

CFLAGS="${COMMON_FLAGS}"
CXXFLAGS="${COMMON_FLAGS}"
FCFLAGS="${COMMON_FLAGS}"
FFLAGS="${COMMON_FLAGS}"

MAKEOPTS="-j4"
USE="wayland gles2 icu python -gnome -systemd"
GENTOO_MIRRORS="https://mirror.aarnet.edu.au/pub/gentoo/"
ACCEPT_LICENSE="*"
GRUB_PLATFORMS="efi-64" # UEFI only
EMERGE_DEFAULT_OPTS="--autounmask-write"

LC_MESSAGES=C
```


```bash
mkdir --parents /mnt/gentoo/etc/portage/repos.conf
cp /mnt/gentoo/usr/share/portage/config/repos.conf /mnt/gentoo/etc/portage/repos.conf/gentoo.conf
cp --dereference /etc/resolv.conf /mnt/gentoo/etc/

mount --types proc /proc /mnt/gentoo/proc
mount --rbind /sys /mnt/gentoo/sys
mount --make-rslave /mnt/gentoo/sys
mount --rbind /dev /mnt/gentoo/dev
mount --make-rslave /mnt/gentoo/dev
mount --bind /run /mnt/gentoo/run
mount --make-slave /mnt/gentoo/run

chroot /mnt/gentoo /bin/bash
source /etc/profile
export PS1="(chroot) ${PS1}"

mount /dev/sda1 /boot
emerge-webrsync
emerge --sync
```


```bash
eselect profile list
eselect profile set X
```

```bash
emerge --verbose --update --deep --newuse @world
emerge app-editors/neovim
```


```bash
ls /usr/share/zoneinfo
echo "Australia/Brisbane" > /etc/timezone
emerge --config sys-libs/timezone-data
```

```bash
nvim /etc/locale.gen
```

```
en_US.UTF-8 UTF-8
```

```bash
locale-gen
eselect locale list
eselect locale set 4 # (US one just made)
env-update && source /etc/profile
```


```
emerge sys-kernel/gentoo-kernel-bin:6.0.12
emerge sys-apps/pciutils
emerge sys-kernel/linux-firmware
```


```bash
eselect kernel set 1
nvim /etc/fstab
```

```bash
/dev/sda1   /boot        vfat    defaults,noatime     0 2
/dev/sda2   none         swap    sw                   0 0
/dev/sda3   /            ext4    noatime              0 1
  
/dev/cdrom  /mnt/cdrom   auto    noauto,user          0 0
```



```
nvim /etc/conf.d/hostname
emerge --noreplace net-misc/netifrc 
ip a
nvim /etc/conf.d/net
```

```bash
config_wlp3s0="dhcp"
modules_wlp3s0="wpa_supplicant"
```

```bash
emerge net-misc/dhcpcd
emerge net-wireless/wpa_supplicant
cd /etc/init.d
ln -s net.lo net.wlp3s0
rc-update add net.wlp3s0 default
rc-service net.wlp3s0 start
rc-service dhcpcd start
```


Install grub (UEFI)
```bash
emerge sys-boot/grub
grub-install --target=x86_64-efi --efi-directory=/boot
grub-mkconfig -o /boot/grub/grub.cfg
```

Install grub (legacy/BIOS)
```bash
emerge sys-boot/grub
grub-install /dev/sda
grub-mkconfig -o /boot/grub/grub.cfg
```


```bash
emerge app-admin/sudo
visudo # uncomment wheel ALL=(ALL:ALL) ALL
useradd -m -G users,wheel,audio,plugdev,video,sddm -s /bin/bash connor
nvim /etc/security/passwdqc.conf # enforce=none
passwd
emerge app-misc/neofetch

su connor
whoami
sudo whoami
reboot
```


```
nvim /etc/wpa_supplicant/wpa_supplicant.conf
```

```bash
ctrl_interface=/var/run/wpa_supplicant
update_config=1
network={
	ssid="..."
	psk="..."
}
```


KDE plasma

<https://wiki.gentoo.org/wiki/KDE>

```
emerge sys-auth/elogind
rc-update add elogind boot

emerge sys-fs/udev
rc-update add udev sysinit

emerge sys-apps/dbus
rc-update add dbus default

emerge sys-auth/polkit
emerge sys-fs/udisks

rc-update add lvm boot
# rc-update add NetworkManager default
reboot

emerge x11-base/xorg-drivers
emerge dev-libs/wayland

emerge kde-plasma/plasma-meta
emerge konsole
emerge kde-apps/kwalletmanager
emerge kde-misc/bismuth
emerge kde-apps/spectacle
emerge kde-apps/dolphin
emerge app-arch/gzip
emerge dev-vcs/git

export $(dbus-launch)
dbus-run-session startplasma-wayland
```

On an Acer Aspire the touchpad did not work, but in BIOS I changed touchpad: advanced to basic and then it worked.

SDDM next

```bash
rc-update add xdm default
emerge x11-misc/sddm
mkdir -p /etc/sddm/scripts
nvim /etc/sddm/scripts/wayland-setup
```

```bash
export $(dbus-launch) && dbus-run-session startplasma-wayland
```

```bash
chmod a+x /etc/sddm/scripts/wayland-setup
nvim /etc/sddm.conf
```

```bash
[wayland]
DisplayCommand=/etc/sddm/scripts/wayland-setup
```

```bash
nvim /etc/conf.d/display-manager
```

```bash
DISPLAYMANAGER="sddm"
```
