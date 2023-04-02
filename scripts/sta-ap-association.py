from scapy.all import *

ifname = ''

# Store a list of AP heard around
aps = {}


def ap_pckts(pkt):
    # Using the Beacon Announce or the Prob Response, we can list the APs around
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        ap_mac = pkt.addr2  # The address 2 is the MAC of the AP
        # If we didn't see it yet, we create a new list
        if ap_mac not in aps:
            aps[ap_mac] = []
        # Then we save the announced SSID with the mac
        ssid = pkt.info.decode()
        aps[ap_mac].append(ssid)


# Start sniffing for APs
sniff(iface=ifname, prn=ap_pckts, store=False)


# Listen for STA and try to match them with AP
def sta_pckts(pkt):
    # Using Probe and Association requests
    if pkt.haslayer(Dot11ProbeReq) or pkt.haslayer(Dot11AssoReq):
        sta_mac = pkt.addr2  #  Get the STA's MAC
        ap_mac = pkt.addr3  #  Get the AP's MAc
        # If the AP is in the AP list, show all associated SSIDs
        if ap_mac in aps:
            for ssid in aps[ap_mac]:
                print(f"AP: {ap_mac} ({ssid}) - STA: {sta_mac}")


# Start sniffing for STAs
sniff(iface=ifname, prn=sta_pckts, store=False)
