from scapy.all import *

ifname = ''

# Goal : List all STA looking for a given SSID

ssid_target = input("Input SSID to target")

def handle_packet(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        ssid = pkt.getlayer(Dot11Elt).info.decode()
        if ssid == ssid_target:
            if pkt.haslayer(Dot11):
                printf(pkt.addr2)
sniff(iface=ifname, prn=handle_packet)