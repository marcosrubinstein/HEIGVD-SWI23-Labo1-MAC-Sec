"""
Titre: 5_b_detect
Sujet: HEIGVD-SWI23-Labo1-MAC-Sec
Description:
    Sniff les réseaux wifi présents et génère une liste des AP présents ainsi que
    des STA associées à ces AP.
Auteurs:
    - Anthony Coke
    - Guilain Mbayo
    - Mehdi Salhi
Date: 30.03.2023
"""

from scapy.all import *

# Liste des STA assocée aux AP
ap_sta_list = []

# Fonction appelée pour traiter chaque paquet
def handle_packet(pkt):
    # Si le paquet = données
    if pkt.type == 2:
        # si le bit toDS est à 1 et fromDS à 0
        # c'est à dire si le paquet est destiné à une AP
        # source: https://stackoverflow.com/questions/52981542/python-scapy-distinguish-between-acesspoint-to-station
        DS = pkt.FCfield & 0x3
        toDS = DS & 0x01 != 0
        fromDS = DS & 0x02 != 0

        if toDS and not fromDS:
            ap_sta = (pkt.addr2, pkt.addr1)

            # Ajout de la pair ap sta dans la liste si pas deja présente et
            # affichage
            if ap_sta not in ap_sta_list:
                ap_sta_list.append(ap_sta)
                print(ap_sta_list[-1][0].upper() + "\t" + ap_sta_list[-1][1].upper())

def main():
    print("Sniffing en cours...")
    print("STAs \t\t\t APs")
    sniff(iface='wlan0mon', prn=handle_packet)

if __name__ == "__main__":
    main()
