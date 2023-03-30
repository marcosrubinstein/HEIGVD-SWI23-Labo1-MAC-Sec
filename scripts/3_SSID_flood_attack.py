from scapy.fields import RandMAC, math
from scapy.layers.dot11 import *
from scapy.utils import *
from random import random
from config import WIFI_INTERFACE_NAME
from threading import Thread
from faker import Faker

# https://scapy.readthedocs.io/en/latest/api/scapy.layers.dot11.html

# sendp(
#     RadioTap()
#     / Dot11(
#         addr1="ff:ff:ff:ff:ff:ff", addr2=randomSenderMac, addr3=randomSenderMac
#     )
#     / Dot11Beacon(cap="ESS", timestamp=1)
#     / Dot11Elt(ID="SSID", info=wifi_ssid)
#     / Dot11EltRates(rates=[130, 132, 11, 22])
#     / Dot11Elt(ID="DSset", info="\x03")
#     / Dot11Elt(ID="TIM", info="\x00\x01\x00\x00"),
#     iface=WIFI_INTERFACE_NAME,
#     loop=1,
# )


def send_beacon(ssid, mac):
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
    # ESS+privacy to appear as secured on some devices
    beacon = Dot11Beacon(cap="ESS")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    frame = RadioTap() / dot11 / beacon / essid
    sendp(frame, inter=0.1, loop=1, iface=WIFI_INTERFACE_NAME, verbose=0)


if __name__ == "__main__":
    # number of access points
    n_ap = 5

    for _ in range(n_ap):
        wifi_name = Faker().name()
        mac = RandMAC()
        print(wifi_name)
        print(mac)
        # Thread(target=send_beacon, args=(wifi_name, RandMAC())).start()
        send_beacon(wifi_name, mac)
