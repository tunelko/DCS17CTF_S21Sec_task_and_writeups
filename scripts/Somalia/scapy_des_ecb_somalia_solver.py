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