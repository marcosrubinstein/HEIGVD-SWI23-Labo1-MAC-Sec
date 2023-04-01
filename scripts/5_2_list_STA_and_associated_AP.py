#!/usr/bin/env python

# Authors:
# - Yanick Thomann
# - Jean Gachet
# - David Gallay
# 
# This script is made for exercise 5.b)
# It scans on the provided interface and displays the STAs and their associated AP


from scapy.all import *
import argparse

Pkt_Info = """
---------------[ Packet Captured ]-----------------------
 Type : {}    Subtype : {}
 From DS : {}    To DS : {}
 Address 1  : {} | Address 2 : {}
 Address 3  : {} | Address 4 : {}
"""

BROADCAST = "ff:ff:ff:ff:ff:ff"


def packet_handler(pkt):
    if pkt.haslayer(Dot11) and pkt.type == 2:  # data packets
        ds = pkt.FCfield & 0x3  # DS bits in the frame control field
        to_ds = ds & 0x1 == 1  # 1st bit is to DS
        from_ds = ds & 0x2 == 1  # 2nd bit is from DS

        # display DS status and addresses (debug)
        # print(Pkt_Info.format(pkt.type, pkt.subtype, from_ds, to_ds, pkt.addr1, pkt.addr2, pkt.addr3, pkt.addr4))

        # Depending on the DS status, STA and AP addresses differ
        # ref: https://mrncciew.files.wordpress.com/2014/09/cwap-mac-address-01.png

        sta_addr = ""
        ap_addr = ""

        # toDS = 0 and fromDS = 0
        if to_ds is False and from_ds is True:
            sta_addr = pkt.addr2
            ap_addr = pkt.addr3

        # toDS = 0 and fromDS = 1
        if to_ds is False and from_ds is True:
            sta_addr = pkt.addr1
            ap_addr = pkt.addr2

        # toDS = 1 and fromDS = 0
        if to_ds is True and from_ds is False:
            sta_addr = pkt.addr2
            ap_addr = pkt.addr1

        # toDS = 1 and fromDS = 1 => not pertinent here

        if sta_addr != "" and ap_addr != "" and pkt.addr1 != BROADCAST:
            print("{}   {}".format(sta_addr, ap_addr))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface")
    args = parser.parse_args()

    # monitoring interface
    interface = "wlp0s20f0u7"  # default interface
    if args.interface is None:
        print("No interface specified, defaulting to " + interface)
    else:
        interface = args.interface

    print("STAs                APs")
    sniff(prn=packet_handler, iface=interface)


if __name__ == "__main__":
    main()
