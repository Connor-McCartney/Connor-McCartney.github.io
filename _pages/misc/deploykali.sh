set -e

sudo apt update
sudo apt upgrade -y
sudo apt install neovim xorg libxft-dev libxinerama-dev libxtst-dev feh picom flameshot alsa-utils libasound2-dev thunar kitty konsole fzf fd-find -y
# have to change fd to fdfind in bashrc
# alacritty is buggy in VM don't use
# sudo visudo
# %sudo ALL=(ALL:ALL) NOPASSWD: ALL

# suckless
cd /tmp
git clone https://github.com/Connor-McCartney/deploy-arch-dwm
mv /tmp/deploy-arch-dwm/suckless /home/connor
cd /home/connor/suckless/dwm && sudo make clean install
cd /home/connor/suckless/dmenu && sudo make clean install
cd /home/connor/suckless/slstatus && sudo make clean install
# https://www.reddit.com/r/debian/comments/1dicswr/libasound2dev_not_working_with_compiler_in/
cd /home/connor/suckless/bongocat && sudo make install

mv /tmp/deploy-arch-dwm/dotfiles/.config/kitty /home/connor/.config
mv /tmp/deploy-arch-dwm/dotfiles/.config/picom /home/connor/.config
rm -rf /tmp/deploy-arch-dwm

printf "sleep 5\nfeh --bg-scale /home/connor/.wallpapers/purple_eyes.png\npicom -b\nslstatus &\nexec dwm" > /home/connor/.xsession 
chmod +x /home/connor/.xsession

mkdir /home/connor/t

cd /tmp
git clone https://github.com/Connor-McCartney/deploy-arch-hyprland/
mv /tmp/deploy-arch-hyprland/dotfiles/.bashrc /home/connor
mv /tmp/deploy-arch-hyprland/dotfiles/.fdignore /home/connor
mv /tmp/deploy-arch-hyprland/dotfiles/.wallpapers /home/connor
mv /tmp/deploy-arch-hyprland/dotfiles/.config/alacritty /home/connor/.config
mv /tmp/deploy-arch-hyprland/dotfiles/.config/nvim /home/connor/.config


sudo apt install -y --reinstall virtualbox-guest-x11

cd /usr/share/fonts 
sudo wget https://dtinth.github.io/comic-mono-font/ComicMono.ttf
fc-cache -fv




sudo chown -R connor:connor ~

printf "done :)"
