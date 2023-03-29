# Source https://stackoverflow.com/questions/52981542/python-scapy-distinguish-between-acesspoint-to-station
from scapy.all import *
from scapy.layers.dot11 import *

INTERFACE = "wlp0s20f3mon"             # Interface to use

associations = {}

def probe_sniff(pkt):
    # Filter wifi probe requests
    if pkt.haslayer(Dot11) and pkt.type == 2: #Data frames
        DS = pkt.FCfield & 0x3
        toDS = DS & 0x01 != 0
        fromDS = DS & 0x2 != 0
        # STA to AP
        if toDS and not fromDS:
            associations[pkt.addr2] = pkt.addr1
        # AP to STA
        if not toDs and fromDS:
            associations[pkt.addr1] = pkt.addr2

if __name__ == '__main__':
    print('Started sniffing, press Ctrl+C to stop...')
    sniff(iface=INTERFACE, prn=probe_sniff)
    print("STAs       APs")
    for k, v in associations.items():
        print(k + '  ' + v)
