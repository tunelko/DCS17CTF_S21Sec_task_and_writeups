# DCS17CTF_S21Sec_task_and_writeups
Tasks, scripts and writeups of most fun or interesting tasks of DCS17CTF (S21SEC)
https://challenge.s21sec.com

#### Somalia - 800 points 

They provide us with a pcapng capture with DNS queries IN A from IPv6 host. This queries were of type Standard Query 0x000 A with some random hexadecimal [hex-host].des. I've been working around the idea of some kind of cipher due ".des" domain termination and after trying some others weird methods (hex->ascii, hex-unxor) that produces nothing.

![](https://blogs.tunelko.com/wp-content/uploads/2017/05/wireshark_exfil.jpg)

Another problem was that UDP source ports appears with strange range (0,117 random) and probably we need to sort in order to get some good outputs. My initial tries produce nothing with unordered streams by udp source ports. So if I was right need to reorder source ports, ‘guess’ cipher key and finally decipher flag. Let’s start.

**Solution 1: tshark to the rescue**

A quickly way to sort those udp source ports that will output only hexadecimal strings of our streams was:

`
tshark -r exfiltracion_111abda47b950e6cd474a43583372c4f.pcapng -Tfields -e udp.srcport -e dns.qry.name |sort -n | cut -f2| sed 's/.des//g'|tr -d "\n"
`

This produces output:


0a73a58aecc21437e1904c8ab6052dc1
a0f76199fa5794ca01e8758aad48de3d
d4b60088a7bb9c279f4f9996e8cb8567
afe260dec74371276b702a5fd30dadd5
d8cd76f9fd75d811236b823593238570
03448e77303587aeb5a3ef036ca8d2cf
d6058a89152f249ea1c0fa0d98f16818
8b9fe0f3f028d7a065b8a1b035746e89
a92f42d82222da6fd19bb7f3a48806b2
e12ee6c61d0ce61d41667e24cd1efa17
b39d6221375e1dbfc4933ecf592f957b
...

Ok, we have all data with correct (asumption) order but what about key for DES-ECB (asumption) cipher. We can try with some data inside the pcap because guessing was too difficult to try and we have a constant field on all the streams: IPv6 field **c7:3f:1d:b9:a2:4:4a:ff**.

Notice is key is 15 bytes and we need a 16-bytes one for decipher ecb-des, so padding left with ‘0’ that ‘alone’ 4. We have all to make our first script to solve the task in our initial assumption.

```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
''' 
DCS17 Challenge S21SEC
Tenemos la sospecha que se han exfiltrado datos, a través de la red.
¿Podrías saber que se ha exfiltrado ?
Fichero: exfiltracion_111abda47b950e6cd474a43583372c4f.pcapng
Puntos: 800 
'''
from Crypto.Cipher import DES
from scapy.all import *
import binascii
 
# Leemos el pcap
pcap = rdpcap("exfiltracion_111abda47b950e6cd474a43583372c4f.pcapng")
 
# Sacamos la key que se deduce de la dirección  ipv6 origen 
key = pcap[1][IPv6].src 
key = key.split(':')
 
# Necesitamos padding para la key c73f1db9a244aff != c73f1db9a2[0]44aff
for i in xrange(len(key)):
    if len(key[i])==1:
        key[i] =  str("0" + key[i])
    ckey = ''.join(key)
 
# Sacamos los paquetes ordenando por puerto UDP origen 
hexdata=''
for packet in sorted(pcap, key= lambda x:x[UDP].sport,reverse=False):
    hexdata += ''.join((packet[DNSQR].qname).replace('.des','').replace('.',''))
 
# Pasamos los datos para descifrarlos con des ecb 
hexdata_to_binary = binascii.unhexlify(hexdata)
key = binascii.unhexlify(ckey)
des = DES.new(key, DES.MODE_ECB)
flag_text = des.decrypt(hexdata_to_binary)
print "#"*100
print flag_text
print "#"*100
```

Hey!, seems that worked. We have a flag, but we can make use of scapy instead of that ugly tshark subprocess command. So refactor python to produce same result:

**Scapy: Infiniteless possibilites**

I don’t know deeper scapy but i know has a lot of possibilities to work on pcap files, so i finally reduce the python script using scapy:

```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
''' 
DCS17 Challenge S21SEC
Tenemos la sospecha que se han exfiltrado datos, a través de la red.
¿Podrías saber que se ha exfiltrado ?
Fichero: exfiltracion_111abda47b950e6cd474a43583372c4f.pcapng
Puntos: 800 
'''
from Crypto.Cipher import DES
from scapy.all import *
import binascii
 
# Leemos el pcap
pcap = rdpcap("exfiltracion_111abda47b950e6cd474a43583372c4f.pcapng")
 
# Sacamos la key que se deduce de la dirección  ipv6 origen 
key = pcap[1][IPv6].src 
key = key.split(':')
 
# Necesitamos padding para la key c73f1db9a244aff != c73f1db9a2044aff
for i in xrange(len(key)):
    if len(key[i])==1:
        key[i] =  str("0" + key[i])
        ckey = ''.join(key)

# Sacamos los paquetes ordenando por puerto UDP origen 
hexdata=''
for packet in sorted(pcap, key= lambda x:x[UDP].sport,reverse=False):
    hexdata += ''.join((packet[DNSQR].qname).replace('.des','').replace('.',''))
 
# Pasamos los datos para descifrarlos con des ecb 
hexdata_to_binary = binascii.unhexlify(hexdata)
key = binascii.unhexlify(ckey)
des = DES.new(key, DES.MODE_ECB)
flag_text = des.decrypt(hexdata_to_binary)
print "#"*100
print flag_text
print "#"*100
```
The equivalent part to the tshark version was the sorted udp source port part with scapy:

```
# Sacamos los paquetes ordenando por puerto UDP origen 
hexdata=''
for packet in sorted(pcap, key= lambda x:x[UDP].sport,reverse=False):
    hexdata += ''.join((packet[DNSQR].qname).replace('.des','').replace('.',''))
```
Finally got the output:

![](https://blogs.tunelko.com/wp-content/uploads/2017/05/scapy_flag.jpg)