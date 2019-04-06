#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" generate an ICMP message and fragment it in 3 parts"""

__author__      = "Olivier Kopp, Florent Piller"
__email__ 		= "olivier.kopp@heig-vd.ch, florent.piller@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
import rc4

#Cle wep AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'

#récuperation du message chiffré comme template
arp = rdpcap('arp.cap')[0]  
ip_packet = [arp, arp, arp]

# generation des parametres du paquet forgé
IV = arp.iv

#creation d'un message icmp
LLC_header = '\xaa\xaa\x03\x00\x00\x00\x08\x00'
IP_header = '\x45\x00\x00\x7f\x00\x00\x40\x00\xaa\x01\x00\x00\xaa\xaa\xaa\xaa\xbb\xbb\xbb\xbb'
ICMP_header = '\x00\x50\x6a\xf6\x00\x64\x00\x00'

plain_wep_data = LLC_header + IP_header + ICMP_header + "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla pharetra sapien id est dignissim sed"

#fragmentation du message en 3
wep_data_fragmented = [plain_wep_data[i:i+len(plain_wep_data)/3] for i in range(0, len(plain_wep_data), len(plain_wep_data)/3)]
ICV_list = []

#seed pour le chiffrement
seed = IV + key

# on effectue toute les opération nécessaire pour chaque fragment
for i in range (0, len(wep_data_fragmented)) :
	ICV = binascii.crc32(wep_data_fragmented[i])
	ICV = struct.pack('<i', ICV)

	#chiffrement du fragment
	wep_data_fragmented[i] = wep_data_fragmented[i] + ICV
	wep_data_fragmented[i] = rc4.rc4crypt(wep_data_fragmented[i], seed)

	#exctraction de l'ICV
	icv_encrypted=wep_data_fragmented[i][-4:]
	(numerical_icv,)=struct.unpack('!L', icv_encrypted)
	ICV_list.insert(len(ICV), numerical_icv)
	
	#exctraction du message sans ICV
	wep_data_fragmented[i] = wep_data_fragmented[i][:-4]

print 'Generating the pcap...'

#modification du paquet pris en template
#writer afin de générer le pcap
pktdump = PcapWriter("fragmented.pcap", append=True, sync=True)

for i in range (0, len(ip_packet)):
	ip_packet[i].icv = ICV_list[i]
	ip_packet[i].wepdata = wep_data_fragmented[i]
	ip_packet[i].SC = i
	#set la valeur more fragment a 1 si il reste des paquet, ou a 0 si c'est le dernier paquet
	ip_packet[i].FCfield = ip_packet[i].FCfield & 0xfb if i+1 == len(ip_packet) else ip_packet[i].FCfield | 0x04
	pktdump.write(ip_packet[i])

