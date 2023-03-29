# Description : Script permettant de detecter les AP avec un SSID caché
# Authors     : Géraud SILVESTI, Alexandre JAQUIER, Francesco MONTI
# Date        : 28.03.2023
# Usage       : 6_hiddenssid.py -i <INTERFACE>
# Source      : https://www.acrylicwifi.com/en/blog/hidden-ssid-wifi-how-to-know-name-of-network-without-ssid/

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, sniff
import argparse
import texttable as text_t

parser = argparse.ArgumentParser(prog="Hidden SSID", description="Find all hidden APs")

parser.add_argument("-i", "--interface", required=True, help="Interface to use for sniffing")
tab_args = parser.parse_args()

# Recherche des SSID cachés (trouve le nom si des probes response sont envoyés)
def find_ssid(packet):
    if packet.haslayer(Dot11Elt):
        # Récupération du SSID (on remplace par rien les caractères \000)
        ssid = packet.info.decode().replace("\000","")
        # Récupération du bssid
        bssid= packet[Dot11].addr3
        # Si c'est une beacon frame --> ssid caché (besoin d'une probe response pour connaitre le ssid)
        if packet.haslayer(Dot11Beacon) and bssid not in ssid_hidden.keys() and ssid == "":
            ssid_hidden[bssid] = "SSID hidden"
        # Si c'est une probe response, on peut découvrir le ssid
        elif (packet.type == 0 and packet.subtype == 5) and bssid in ssid_hidden.keys():
            ssid_hidden[bssid] = ssid

# Affichage des informations sous forme de table
def display_list(list):
    if len(list) == 0:
        print("No hidden SSID found")
        return
    
    table = text_t.Texttable()
    table.set_deco(text_t.Texttable.HEADER)
    table.set_cols_dtype(['i','t','t']) 
    table.set_cols_align(["l", "l", "l"])
    table.add_row(["No", "BSSID", "SSID"])

    i = 0
    for key, value in list.items():
        i += 1
        table.add_row([i, key, value])
    print(table.draw())

# Execution du script
if __name__ == "__main__":
    ssid_hidden = dict()
    print("Scanning for hidden SSID...")
    sniff(iface=tab_args.interface, prn=find_ssid, timeout=20)
    display_list(ssid_hidden)