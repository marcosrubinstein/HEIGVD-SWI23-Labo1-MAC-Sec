from scapy.all import *
import os

# Define the filter to capture only Wi-Fi packets
wifi_filter = "wlan"

# Configure the network interface in monitor mode
interface = "wlan0mon"
os.system(f"sudo ip link set {interface} down")
os.system(f"sudo iw dev {interface} set type monitor")
os.system(f"sudo ip link set {interface} up")

# Capture Wi-Fi packets for 10 seconds
packets = sniff(iface=interface, timeout=15)

# Analyze each packet to extract the SSID
for packet in packets:
    if packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 0:
        bssid = packet.addr3
        ssid = packet[Dot11Elt].info.decode()
        print(f"BSSID: {bssid}, SSID: {ssid}")

print(f"end of script")
# Restore the network interface to its original state
os.system(f"sudo ip link set {interface} down")
os.system(f"sudo iw dev {interface} set type managed")
os.system(f"sudo ip link set {interface} up")

