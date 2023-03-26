#!/usr/bin/env python
from swi_utils import (
    DEFAULT_IFACE,
    find_ap,
    ask_ap_to_spoof
)

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

def main():
    interface, packet_count, channels = handle_arguments()
    AP_LIST = find_ap(interface, packet_count, channels)
    target = ask_ap_to_spoof(AP_LIST)
    target.spoof(interface, spoof_mac=True)

def test():
    interface, packet_count, channels = handle_arguments()
    AP_LIST = find_ap(interface, packet_count, channels)
    target = ask_ap_to_spoof(AP_LIST)
    print(target.bssid)
    target.spoof(interface, ssid="test SWI", randmac=True)


if __name__ == "__main__":
    main()
    # beacon(
    #     'testSSID',
    #     '22:22:22:22:22:22',
    #     '33:33:33:33:33:33',
    # )
    # test()