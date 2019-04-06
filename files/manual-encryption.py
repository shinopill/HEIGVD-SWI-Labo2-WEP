#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key and the message"""

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

# generation des parametres du paquet forgé
IV = arp.iv

#LLC header
LLC_header = '\xaa\xaa\x03\x00\x00\x00\x08\x06'

#generation d'une fausse réponse ARP de la demande de l'exercice 1
Hardware_type = '\x00\x01' # Ethernet
Prot = '\x08\x00' # ipv4
Hardware_size = '\x06'
Prot_size = '\x04'
Opcode = '\x00\x02' # reply
Sender_mac = '\xaa\xbb\xcc\xdd\xee\xff'
Sender_ip = '\xc0\xa8\x01\xc8'
Target_mac = '\x90\x27\xe4\xea\x61\xf2'
Target_ip = '\xc0\xa8\x01\x64'

plain_wep_data = LLC_header + Hardware_type + Prot + Hardware_size + Prot_size + Opcode + Sender_mac + Sender_ip + Target_mac + Target_ip

seed = IV + key

# calcul de l'ICV du message et concatenation de celui-ci avec le message en clair
ICV = binascii.crc32(plain_wep_data)
ICV = struct.pack('<i', ICV)

plain_wep_data_with_ICV = plain_wep_data + ICV

#chiffrement du texte
cipher_wep_data_with_ICV = rc4.rc4crypt(plain_wep_data_with_ICV, seed)

# le ICV correspond aux 4 derniers octets - on le passe en format Long big endian
icv_encrypted=cipher_wep_data_with_ICV[-4:]
(numerical_icv,)=struct.unpack('!L', icv_encrypted)

# le message sans le ICV
cipher_wep_data=cipher_wep_data_with_ICV[:-4] 

print 'Generating the ARP packet...'

#modification du paquet pris en template
forged_arp = arp
forged_arp.icv = numerical_icv
forged_arp.wepdata = cipher_wep_data

#generation du fichier pcap
wrpcap('forged_arp.cap', forged_arp)

