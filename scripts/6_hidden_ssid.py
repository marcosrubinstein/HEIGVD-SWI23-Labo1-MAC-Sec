#!/bin/python

from scapy.all import *
import numpy as np

def main():
    print("Récupération des trames Beacon...", end=' ', flush=True)
    # On écoute pendant 30s les trames de type beacon
    frame_arr = sniff(iface="wlan0", filter="(type mgt) and (subtype beacon or subtype proberesp)", timeout=30)
    print("[OK]", flush=True)

    # On récupère toutes les adresses MAC qui ont un SSID caché
    ssid_dict = {}
    for frame in frame_arr:
        # Si Beacon
        if frame.subtype == 8:
            ssid_name = frame.getlayer(Dot11Beacon).info.decode()
            # On ne souhaite pas récupérer les SSIDs non-masqués
            if ssid_name.rstrip('\x00') != '':
                continue
            ssid_dict[frame.addr3] = ''


    # On récupère les Probe Response qui nous permettent de démasquer les SSIDs cachés
    for frame in frame_arr:
        # Si Probe Response
        if frame.subtype == 5 and frame.addr3 in ssid_dict.keys():
            ssid_dict[frame.addr3] = frame.info.decode()


    # Affichage des résultats
    print(f"Adresse MAC de l'AP {'SSID'.ljust(32)}")
    for i, mac in enumerate(ssid_dict.keys()):
        ssid = ssid_dict[mac]
        print(f"{str(mac).rjust(2)}: {ssid.ljust(32)}")


if __name__ == "__main__":
    main()
