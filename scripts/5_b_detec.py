from scapy.all import *

ap_list = set()  # ensemble des adresses MAC des AP détectés
sta_list = {}    # dictionnaire pour stocker les STA associées à chaque AP détecté

def handle_packet(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 8:  # beacon frame
            ap_mac = pkt.addr2
            ap_list.add(ap_mac)
        elif pkt.type == 2 and pkt.subtype == 0:  # data frame
            sta_mac = pkt.addr2
            ap_mac = pkt.addr3
            if ap_mac in ap_list:
                sta_list[sta_mac] = ap_mac

# capture de paquets Wi-Fi pendant 10 secondes
sniff(iface='wlan0mon', prn=handle_packet, timeout=10)

# affichage des résultats
print("STAs\t\tAPs")
for sta_mac, ap_mac in sta_list.items():
    print(sta_mac, "\t", ap_mac)
