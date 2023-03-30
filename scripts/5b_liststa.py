# Description : Script permettant de detecter les STA cherchant un SSID donné
# Authors     : Géraud SILVESTI, Alexandre JAQUIER, Francesco MONTI
# Date        : 28.03.2023
# Usage       : 4_evilTwin.py -i <INTERFACE> -s <SSID>

from scapy.all import sniff
import argparse

list_STA = []

parser = argparse.ArgumentParser(prog="List STA", description="List STA who research SSID")

parser.add_argument("-i", "--interface", required=True, help="Interface to use for sniffing")
parser.add_argument("-s", "--SSID", required=True, help="SSID to look for")
args = parser.parse_args()

# Recherche des paquets probe ayant un SSID défini
def sta_finder(packet):
    # Le paquet doit être une probe, être le SSID que l'on cherche et ne pas faire déjà partie de la liste
    if packet.type == 0 and packet.subtype == 4 and args.SSID == packet.info.decode() and packet.addr2 not in list_STA:
            list_STA.append(packet.addr2)
            print(packet.addr2)

if __name__ == "__main__":
    print("List of stations who are looking for the AP with SSID : " + args.SSID + "\n")
    sniff(iface=args.interface, prn=sta_finder)