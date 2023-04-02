from scapy.all import *

# Goal : List all STA looking for a given SSID

ifname = ''

ssid_target = input("Input SSID to target")


# Print MAC address of STA requesting a given SSID
def handle_packet(pkt):
    if pkt.haslayer(Dot11ProbeReq):  # If it's a probe request
        ssid = pkt.getlayer(Dot11Elt).info.decode()  # Retrieve SSID
        if ssid == ssid_target:  # If it's the target
            if pkt.haslayer(Dot11):  # Check if the Dot11 is included
                printf(pkt.addr2)  # Show the STA's MAC


sniff(iface=ifname, prn=handle_packet)
