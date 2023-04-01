#!/usr/bin/env python3

# Authors:
# - Yanick Thomann
# - Jean Gachet
# - David Gallay
# 
# This script is made for exercise 4
# Scans all channels to find SSIDs by listerning to Probe Requests and then emit a spoofed beacon that match one of the probed AP

# Source: https://gist.github.com/securitytube/5291959


from swi_utils import (
    find_ap_by_probe_request_timeout,
    find_ap,
    ask_ap_to_spoof,
    DEFAULT_IFACE
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

def main(limit_to_local=False):
    interface, packet_count, channels = handle_arguments()

    ap_list = find_ap_by_probe_request_timeout()
    if limit_to_local:
        local_ap = find_ap()
        ap_list = list(set(ap_list).intersection(set(local_ap)))
    target = ask_ap_to_spoof(ap_list)
    target.spoof(
        interface,
        # spoof_mac=True  # uncomment this line to also spoof the MAC address of the device
    )



if __name__ == "__main__":
    main()
