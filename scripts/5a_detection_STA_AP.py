from scapy.all import *
from config import WIFI_INTERFACE_NAME


def packet_handler(packet, ssid):
    isProbeRequest = packet.haslayer(Dot11ProbeReq)  # Show only prob requests
    ssidSearched = packet.getlayer(Dot11ProbeReq).info.decode()  # with the ssid asked

    if isProbeRequest and ssidSearched == ssid:
        print(f"STA '{packet.addr2}' is looking for the AP")


if __name__ == "__main__":
    ssid = input("Enter the SSID you want to spy on (searching STAs) : ")
    print(f"STAs looking for AP: {ssid}")
    sniff(iface=WIFI_INTERFACE_NAME, prn=lambda packet: packet_handler(packet, ssid))
