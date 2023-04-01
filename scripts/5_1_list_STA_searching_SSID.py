#!/usr/bin/env python

# Authors:
# - Yanick Thomann
# - Jean Gachet
# - David Gallay
# 
# This script is made for exercise 5.a)
# It scans on the provided interface and displays the MAC address of devices that probed the given SSID

from scapy.all import *
import argparse

SSID = ""


def packet_handler(pkt):
    # if the packet is a probe request for the chosen SSID, displays the MAC address
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 4 and pkt.info.decode() == SSID:
        print("{} probed {}".format(pkt.addr2, SSID))


def main():
    global SSID

    # script arguments:
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--ssid")  # SSID to monitor
    parser.add_argument("-i", "--interface")  # interface from where to capture traffic
    args = parser.parse_args()

    # SSID
    if args.ssid is None:
        SSID = input("Choose the SSID to monitor: ")
    else:
        SSID = args.ssid
    print("SSID plop: " + SSID)

    # monitoring interface
    interface = "wlp0s20f0u7"  # default interface
    if args.interface is None:
        print("No interface specified, defaulting to " + interface)
    else:
        interface = args.interface

    # captures traffic on the interface and transfers the packets to the handler
    sniff(prn=packet_handler, iface=interface)


if __name__ == "__main__":
    main()
