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
def send_beacon(ssid, mac, interface,  infinite=True):
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    frame = RadioTap() / dot11 / beacon / essid
    sendp(frame, inter=0.1, loop=1, iface=interface, verbose=0)


ssid_array = []


def do_stuff(path, interface):
    if path == None:
        # Pas de fichier, on demande combien de SSID on génère et on les crée aléatoirement
        nbr_ssid = int(input("Combien de SSID faut-il créer ? "))
        for i in range(nbr_ssid):
            ssid_array.append(Faker().company())
    else:
        if os.path.isfile(path):
            my_file = open(path, "r")
            for line in my_file:
                if line != "\r\n" or line != "" or line != "\n":
                    ssid_array.append(line.rstrip())

    # On crée un Thread qui exécute la fonction send_beacon pour chaque SSID de la liste
    for ssid_name in ssid_array:
        print(ssid_name)
        Thread(target=send_beacon, args=(ssid_name, Faker().mac_address(), args.i)).start()


do_stuff(args.f, args.i)
