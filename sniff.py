from scapy.all import *

def traitemet(paquet):
    for pkt in paquet:
        print(pkt.summary())

sniff(prn=traitemet)

