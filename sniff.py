from scapy.all import *

# traitement des paquets capturés
def traitemet(paquet):
    for pkt in paquet:
        print(pkt.summary())

sniff(prn=traitemet)

