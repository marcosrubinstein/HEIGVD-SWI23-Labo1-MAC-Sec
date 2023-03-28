from scapy.all import *
import argparse

# Create an empty list to store the MAC addresses of stations that are looking for the specified SSID
stationsList = []

# Create an argument parser to allow the user to provide the SSID to look for
parser = argparse.ArgumentParser(prog="STA listing", description="Lists all the stations that look for a particular SSID")
parser.add_argument("-s", "--SSID", required=True, help="SSID to look for")
args = parser.parse_args()

# Function to check if a packet is a Probe-Request for the specified SSID and add the MAC address to the stations list
def listStations(pkt):
    # Check if the packet is a Probe-Request (subtype 4), if the SSID is the one we're looking for, and if it's not already in the stations list.
    if pkt.type == 0 and pkt.subtype == 4 and args.SSID == pkt.info.decode() and pkt.addr2 not in stationsList:
            stationsList.append(pkt.addr2) # Add the STA to the list if everything corresponds
            print(pkt.addr2)

if __name__ == '__main__':
    # Print the SSID that the script is looking for
    print("Stations looking for the SSID: " + args.SSID + "\n")
    # Use Scapy's sniff function to capture and process packets on the specified interface
    sniff(iface="wlan0", prn=listStations)
