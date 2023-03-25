#!/usr/bin/env python

from scapy.all import *
import sys
import argparse

Pkt_Info = """
---------------[ Packet Captured ]-----------------------
 Subtype  : {}   
 Address 1  : {} | Address 2 : {}
 Address 3  : {} | Address 4 : {}
 AP   : {} [SSID]
"""

ssid = ""

def filter_ssid_probe_requests(pkt):
    print(Pkt_Info.format(pkt.subtype,pkt.addr1, pkt.addr2, pkt.addr3, pkt.addr4, pkt.info))
    if pkt[Dot11Elt].info.decode() == ssid:
        print(pkt.addr2)

def main():
    global ssid
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--ssid")
    parser.add_argument("-i", "--interface")
    args = parser.parse_args()
    
    # SSID
    if args.ssid == None:
        ssid = input("Choose the SSID to monitor: ")
    else:
        ssid = args.ssid
    print("SSID plop: " + ssid)
        
    # monitoring interface
    interface = ""
    if args.interface == None:
        print("No interface specified, defaulting to wlp0s20f0u7")
        interface = "wlp0s20f0u7"
    else:
        interface = args.interface
        
    sniff(prn=filter_ssid_probe_requests, iface=interface, filter="type mgt subtype probe-req")
    
if __name__ == "__main__":
    main()
