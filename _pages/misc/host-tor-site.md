---
permalink: /misc/host-tor-site
title: How to host your website on the TOR network
---

<br>


Hosting a website on the TOR network is shockingly easy, and doesn't even require port forwarding. 

First you want to have your server (E.g. Apache or Nginx) running and pointing at http://localhost:8080

If you don't have one you can test with a simple python one:

```python
python -m http.server --bind 127.0.0.1 8080
```

Then install the TOR client if you don't already have it:

```
sudo dnf install tor
```

Now edit /etc/tor/torrc and uncomment these lines:

```
HiddenServiceDir /var/lib/tor/hidden_service/
HiddenServicePort 80 127.0.0.1:8080
```

Now just start the TOR client and you are done!

```
sudo systemctl enable tor
sudo systemctl start tor
```

View the .onion address with:

```
sudo cat /var/lib/tor/hidden_service/hostname
```
