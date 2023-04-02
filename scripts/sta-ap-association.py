from scapy.all import *

ifname = ''

# Store a list of AP heard around
aps = {}


def ap_pckts(pkt):
    # Using the Beacon Announce or the Prob Response, we can list the APs around
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        ap_mac = pkt.addr2  # The address 2 is the MAC of the AP
        # Saving the announced SSID with the mac
        ssid = pkt.info.decode()
        aps[ap_mac] = ssid


# Start sniffing for APs
sniff(iface=ifname, prn=ap_pckts, store=False)


# Listen for STA and try to match them with AP
def sta_pckts(pkt):
    # Using Probe and Association requests
    if pkt.haslayer(Dot11ProbeReq) or pkt.haslayer(Dot11AssoReq):
        sta_mac = pkt.addr2  # Get the STA's MAC
        ap_mac = pkt.addr3  # Get the AP's MAc
        # If the AP is in the AP list, show associated SSID
        if ap_mac in aps:
            print(f"AP: {ap_mac} ({aps[ap_mac]}) - STA: {sta_mac}")


# Start sniffing for STAs
sniff(iface=ifname, prn=sta_pckts, store=False)
