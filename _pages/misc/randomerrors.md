---
permalink: /misc/randomerrors
title: Random Errors
---



<br>

Ever encounter some error that you know you've seen before but you forgot what you did?

Yeah that's what I'm gonna try use this page for....

<br>

<br>

---


# 1

### problem

```
$ sudo openvpn user-config-18e2fd18-f0ab-4b8c-a5af-2fa045b7c3c0.ovpn
2026-08-05 17:59:04 DEPRECATED OPTION: --persist-key option ignored. Keys are now always persisted across restarts. 
Options error: --up script fails with '/etc/openvpn/update-resolv-conf': No such file or directory (errno=2)
Options error: Please correct this error.
Use --help for more information.
```

### fix

```
$ yay -S aur/openvpn-update-resolv-conf-git
```



<br>

<br>

