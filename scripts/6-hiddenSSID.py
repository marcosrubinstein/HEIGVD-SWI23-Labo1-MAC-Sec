# Source : https://www.youtube.com/watch?v=_OpmfE43AiQ

from scapy.layers.dot11 import *

INTERFACE = "wlp0s20f3mon"             # Interface to use

hidden = set()

# Method to offer an evil twin for a particular SSID
def probe_sniff(pkt):
    # Filter wifi probe requests
    if pkt.haslayer(Dot11Beacon):
        if not pkt.info:
            if pkt.addr3 not in hidden:
                hidden.add(pkt.addr3)
                print("Found hidden SSID :", pkt.addr3)
    elif pkt.haslayer(Dot11ProbeResp) and (pkt.addr3 in hidden):
        print("SSID uncovered :", pkt.addr3, pkt.info.decode())


if __name__ == '__main__':
    print('Started sniffing, press Ctrl+C to stop...')
    sniff(iface=INTERFACE, prn=probe_sniff)
