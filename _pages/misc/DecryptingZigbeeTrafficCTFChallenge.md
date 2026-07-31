---
permalink: /misc/DecryptingZigbeeTrafficCTFChallenge
title: Decrypting Zigbee Traffic CTF Challenge
---



<br>


<br>


<br>


[Challenge PCAP](https://github.com/Connor-McCartney/CTF_Files/tree/main/2026/ADF_HTB)


<br>


<br>


<br>

```python
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers.aead import AESCCM


# https://community.hubitat.com/t/how-i-setup-wireshark-to-capture-zigbee-messages/149452
trusted_network_key = b'ZigBeeAlliance09' # default for every zigbee network

# there is a network key in the pcap but that has to be decrypted!
encrypted_network_key = bytes.fromhex('328da53757f3e5cf09fe8326942326de')
network_key = AES.new(trusted_network_key, AES.MODE_ECB).decrypt(encrypted_network_key)
print(f'{network_key.hex() = }')  # this can also be pasted into Wireshark, ctrl-shift-p > protocols > zigbee






# flag is in packet 23 (0x0015)

frame_counter = "1500000000000000"
counter_value = "01000000"
security_control = "2d"
nonce = bytes.fromhex(frame_counter+ counter_value + security_control)
assert len(nonce) == 13

authenticated_data = bytes.fromhex(
    "0812000015000a071500000000000000" # NWK header
    "2d01000000150000000000000000" # 2d01000000150000000000000000
)
ciphertext = bytes.fromhex("cb79821ab489734bc60b533b53b7a913041efdc992d156161ecea28c1f905920b63b6ca0348b4f689b51f16fc781e72f98")
mic = bytes.fromhex("f6572b06")

plaintext = AESCCM(network_key, tag_length=len(mic)).decrypt( nonce, ciphertext + mic, authenticated_data)
print(plaintext[16:]) # HTB{Z1gB33_N3tw0rk_K3y_3xtr4ct3d}
```


<br>

<br>



