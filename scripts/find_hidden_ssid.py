from scapy.all import *
import os

# Define the filter to capture only Wi-Fi packets
wifi_filter = "wlan type mgt"

# Configure the network interface in monitor mode (interface may have to be
# changed)
interface = "wlan0mon"
os.system(f"sudo ip link set {interface} down")
os.system(f"sudo iw dev {interface} set type monitor")
os.system(f"sudo ip link set {interface} up")


# set the list of Wi-Fi channels to scan
channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]

# scan each channel
for channel in channels:
    os.system(f"sudo iwconfig {interface} channel {channel}")
    print(f"Scanning channel {channel}...")

    packets = sniff(filter=wifi_filter, iface=interface, timeout=5)

    # Analyze each packet to extract the SSID
    for packet in packets:
        if packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 0:
            bssid = packet.addr3
            addr1 = packet.addr1
            addr2 = packet.addr2
            ssid = packet[Dot11Elt].info.decode()
            print(f"BSSID: {bssid}, RA/DA: {addr1}, TA/SA: {addr2}, SSID: {ssid}")

print(f"end of script")
# Restore the network interface to its original state
os.system(f"sudo ip link set {interface} down")
os.system(f"sudo iw dev {interface} set type managed")
os.system(f"sudo ip link set {interface} up")

