from scapy.fields import math
from scapy.layers.dot11 import *
from scapy.utils import *
from random import random

# https://scapy.readthedocs.io/en/latest/api/scapy.layers.dot11.html
ssids = ["wifi1", "wifi2", "wifi3"]
wifi_name = randstring(math.floor(random() * 6) + 5)

sendp(
    RadioTap()
    / Dot11(
        addr1="ff:ff:ff:ff:ff:ff", addr2="00:01:02:03:04:05", addr3="00:01:02:03:04:05"
    )
    / Dot11Beacon(cap="ESS", timestamp=1)
    / Dot11Elt(ID="SSID", info=wifi_name)
    / Dot11EltRates(rates=[130, 132, 11, 22])
    / Dot11Elt(ID="DSset", info="\x03")
    / Dot11Elt(ID="TIM", info="\x00\x01\x00\x00"),
    iface="wlan0",
    loop=1,
)
