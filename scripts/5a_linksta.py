# Description : Script permettant de detecter les STA cherchant un AP
# Authors     : Géraud SILVESTI, Alexandre JAQUIER, Francesco MONTI
# Date        : 28.03.2023
# Usage       : 5a_linksta.py -i <INTERFACE>

from scapy.all import sniff, Dot11Elt
import argparse

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
list_sta_ap = []


parser = argparse.ArgumentParser(prog="Link AP-STA", description="Look for STA who are linked to an AP")
parser.add_argument("-i", "--interface", required=True, help="Interface to use for sniffing")
args = parser.parse_args()

# Check les STA qui sont liées à un AP
def link_sta_ap(packet):
    # Uniquement paquets de type 2 (permettent de confirmer le lien entre une STA et AP)
    if packet.type == 2:
        # Check que l'on diffuse pas vers un broadcast (mais bien d'un AP vers STA / STA vers AP)
        if packet.addr1 != BROADCAST_MAC and packet.addr2 != BROADCAST_MAC and packet.addr3 is not None:
            # On check que la première adresse est la STA et ensuite l'AP, sinon on modifie
            if packet.addr1 != packet.addr3:
                sta_ap = (packet.addr1, packet.addr3)
            else:
                sta_ap = (packet.addr2, packet.addr3)
            
            # Si le lien STA-AP n'est pas déja connu, on l'ajoute et affiche
            if sta_ap not in list_sta_ap:
                list_sta_ap.append(sta_ap)
                print(sta_ap[0]+" \t\t "+sta_ap[1])

if __name__ == "__main__":
    print("List of STA and AP link")
    print("STA \t\t\t\t AP")
    sniff(iface=args.interface, prn=link_sta_ap)

