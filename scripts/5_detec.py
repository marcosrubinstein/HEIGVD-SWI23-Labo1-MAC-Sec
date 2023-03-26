from scapy.all import *

ssid = input("Entrez le ssid recherché: ")

def packet_handler(packet):
    if packet.haslayer(Dot11ProbeReq) and packet.info.decode('utf-8') == ssid:
        print("STA '{}' cherche AP '{}'".format(packet.addr2, ssid))

print("Sniffing en cours....")
sniff(iface="wlan0mon", prn=packet_handler)
