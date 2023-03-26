from scapy.all import *
import argparse
parser = argparse.ArgumentParser(prog="Find STAs", description="Find STAs who search a specific SSID")
parser.add_argument("-i", required=True, help="Interface to use")
parser.add_argument("-s", required=True, help="SSID to search")
args = parser.parse_args()


sta_list = []
def sta_finder(pkt):
    # Le paquet doit être un probe + être le SSID que l'on cherche + ne pas faire déjà partie de la liste (ne liste pas 2 fois le même)
    if pkt.type == 0 and pkt.subtype == 4 and args.s == pkt.info.decode() and pkt.addr2 not in sta_list:
        sta_list.append(pkt.addr2)
        print(pkt.addr2)

print("List of STAs looking for " + args.s + ": \n")
sniff(iface=args.i, prn=sta_finder)