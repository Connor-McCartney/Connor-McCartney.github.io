---
permalink: /misc/scapy
title: Scapy HTTP/HTTPS sniffing
---

<br>

Simple HTTP and HTTPS sniffers using Scapy https://scapy.readthedocs.io/en/latest/usage.html

<br>

# HTTP

```python
from scapy.all import sniff
from scapy.layers.http import HTTPRequest, Raw


def http_sniff(packet):
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        print(url)
        if packet.haslayer(Raw):
            data = packet[Raw].load.decode()
            print(data)

            
def main():
    print("HTTP sniffing started...")
    sniff(filter="port 80", prn=http_sniff)

    
if __name__ == "__main__":
    main()
```

<br>

# HTTPS

<br>

```python
from scapy.all import sniff, IP
from scapy.layers.http import HTTPRequest
from socket import gethostbyaddr, herror


duplicates = []

def https_sniff(packet):
    if packet.haslayer(HTTPRequest) or packet.haslayer(IP):
        dest_ip = packet[IP].dst 
        if dest_ip not in duplicates:
            try:
                host = gethostbyaddr(dest_ip)[0]
            except herror:
                host = ""
            duplicates.append(dest_ip)
            print(dest_ip + " "*(20-len(dest_ip)) + host)

            
def main():
    print("HTTPS sniffing started...")
    sniff(filter="port 443", prn=https_sniff)

    
if __name__ == "__main__":
    main()
```
