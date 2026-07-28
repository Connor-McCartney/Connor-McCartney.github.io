


<br>

Choose the x86-64

<br>

login as root (password not required)

<br>

run setup-alpine to install

You can leave most things default, just change root password, create a user, and choose the disk, choose sys



<br>

---

apk is the package manager, you can do apk search ... and apk add ... 

hyperv didn't seem to work but VMware did...


<br>

---

<br>


Alpine seems to have a built-in `setup-xorg-base` command you can run.

vi ~/.xinitrc

```
exec dwm
```


<br>



<br>

I'll reuse my setup from <https://github.com/Connor-McCartney/deploy-arch-dwm/blob/main/user.sh>


<br>

apk add git

apk add make

apk add build-base

apk add libx11-dev

apk add libxft-dev

apk add libxinerama-dev

<br>



```
# suckless
cd /tmp
git clone https://github.com/Connor-McCartney/deploy-arch-dwm
mv /tmp/deploy-arch-dwm/suckless /home/connor
cd /home/connor/suckless/dwm && sudo make clean install
cd /home/connor/suckless/dmenu && sudo make clean install
cd /home/connor/suckless/slstatus && sudo make clean install
#cd /home/connor/suckless/bongocat && sudo make install
cd /home/connor/suckless/desktop_kirby && chmod +x build.sh && ./build.sh
rm -rf /tmp/deploy-arch-dwm
```


<br>


<br>

<br>



