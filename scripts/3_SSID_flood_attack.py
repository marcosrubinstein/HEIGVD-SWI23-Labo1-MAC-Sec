from scapy.fields import RandMAC
from scapy.layers.dot11 import *
from scapy.utils import *
from config import WIFI_INTERFACE_NAME
from threading import Thread
from faker import Faker

# https://scapy.readthedocs.io/en/latest/api/scapy.layers.dot11.html


def send_beacon(ssid, mac):
    # subtype 8 : Beacon
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)

    # ESS+privacy to appear secured
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    others = (
        Dot11EltRates(rates=[130, 132, 11, 22])
        / Dot11Elt(ID="DSset", info="\x03")
        / Dot11Elt(ID="TIM", info="\x00\x01\x00\x00")
    )

    frame = RadioTap() / dot11 / beacon / essid / others
    sendp(frame, inter=0.1, loop=1, iface=WIFI_INTERFACE_NAME, verbose=0)


if __name__ == "__main__":
    choice = int(
        input(
            "--- Fake AP Generator ---\n"
            + "[1] Generate N random AP\n"
            + "[2] Generate AP from list file\n"
            + "> "
        )
    )

    n_ap = 0
    if choice == 1:
        n_ap = int(input("Enter the number of fake AP: "))
    elif choice == 2:
        wifi_names = []
        fileName = input("Enter the file path of the AP list: ")
        with open(fileName, "r") as file:
            # read wifi names from file (values are separated with returns)
            wifi_names = [x for x in file.read().split("\n") if x != ""]
        n_ap = len(wifi_names)

    for i in range(n_ap):
        if choice == 1:
            # Wifi random name is taken from the faker package
            wifi_name = Faker().name()
        else:
            wifi_name = wifi_names[i]

        mac = RandMAC()
        print(f"{wifi_name} : {mac}")  # Fake AP are displayed
        Thread(
            target=send_beacon, args=(wifi_name, mac)
        ).start()  # Launch one thread per wifi created to be parallelised
