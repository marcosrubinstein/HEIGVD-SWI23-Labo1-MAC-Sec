from scapy.all import *
from config import WIFI_INTERFACE_NAME

staKnown = []


def packet_handler(packet, ssid):
    if not packet.haslayer(Dot11ProbeReq):  # Show only prob requests
        return

    ssidSearched = packet.getlayer(Dot11ProbeReq).info.decode()  # with the ssid asked

    sta = packet.addr2
    if ssidSearched == ssid and sta not in staKnown:
        print(f"STA '{sta}' is looking for the AP")
        staKnown.append(sta)


if __name__ == "__main__":
    ssid = input("Enter the SSID you want to spy on (searching STAs) : ")
    print(f"STAs looking for AP: {ssid}")
    sniff(iface=WIFI_INTERFACE_NAME, prn=lambda packet: packet_handler(packet, ssid))
