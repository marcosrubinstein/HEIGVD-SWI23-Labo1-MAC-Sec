from scapy.all import *

def ssid_scan_callback(packet):
    if packet.haslayer(Dot11ProbeReq) and packet.info.decode() == target_ssid:
        print(f"Device with MAC {packet.addr2} is searching for SSID {target_ssid}")

target_ssid = input("Enter the target SSID: ")
print(f"Scanning for devices searching for SSID {target_ssid}...")
sniff(iface="wlan0", prn=ssid_scan_callback)
