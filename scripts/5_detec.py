"""
Titre: 5_detect
Sujet: HEIGVD-SWI23-Labo1-MAC-Sec
Description:
    Liste toutes les STA qui cherchent activement un SSID donné
Auteurs:
    - Anthony Coke
    - Guilain Mbayo
    - Mehdi Salhi
Date: 30.03.2023
"""

from scapy.all import *

ssid = input("Entrez le ssid recherché: ")

# Fonction appelée pour traiter chaque paquet
def packet_handler(packet):
    # Affiche la STA si le paquet est une ProveRequest et si le SSID correspond
    # à celui entré par l'utilisateur
    if packet.haslayer(Dot11ProbeReq) and packet.info.decode('utf-8') == ssid:
        print("STA '{}' cherche AP '{}'".format(packet.addr2, ssid))

print("Sniffing en cours....")
sniff(iface="wlan0mon", prn=packet_handler)
