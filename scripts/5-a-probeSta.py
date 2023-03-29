
from scapy.layers.dot11 import *

INTERFACE = "wlp0s20f3mon"             # Interface to use
SSID = "netplus-1ee13f"                # Probe Requests to answer to

# Method to offer an evil twin for a particular SSID
def probe_sniff(pkt):
    # Filter wifi probe requests
    if pkt.haslayer(Dot11ProbeReq):
        # Filter SSID of interest
        if pkt.getlayer(Dot11ProbeReq).info.decode() == SSID:
            # Display the MAC address of the STA looking for the network
            client_mac = pkt.getlayer(Dot11).addr2
            print(f'{client_mac} is looking for {SSID}')

if __name__ == '__main__':
    print('Started sniffing, press Ctrl+C to stop...')
    sniff(iface=INTERFACE, prn=probe_sniff)
