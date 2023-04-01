#!/usr/bin/env python

# Authors:
# - Yanick Thomann
# - Jean Gachet
# - David Gallay
# 
# This file provide utility function shared across the scripts



# https://www.4armed.com/blog/forging-wifi-beacon-frames-using-scapy/

from scapy.all import (
    Dot11,
    Dot11Beacon,
    # Dot11ProbeResp,
    Dot11ProbeReq,
    Dot11Elt,
    RadioTap,
    sendp,
    hexdump,
    RandMAC,
)
from functools import partial, wraps

DEFAULT_IFACE = "wlan0mon"
DEFAULT_CHANNEL = 1

# Adresse 1: Adresse finale qu'on veut joindre
# Adresse 2: celui qui emet la trame
# Adresse 3: Adresse du prochain noeud ?
#

# ====================================================================================================
# START utilities definition

def spoof_mac(iface, mac_addr):
    """
        In order to completly fake the AP, we need to change the device MAC address
        This will use the `macchanger` command
    """
    try:
        os.system("""ifconfig {} down""".format(iface))
        os.system("""macchanger --mac={mac_addr} {iface}""".format(
            iface=iface,
            mac_addr=mac_addr,
        ))
        os.system("""ifconfig {} up""".format(iface))
    except Exception:
        pass
def reset_mac(iface):
    try:
        os.system("""ifconfig {} down""".format(iface))
        os.system("""macchanger -p {iface}""".format(
            iface=iface,
        ))
        os.system("""ifconfig {} up""".format(iface))
    except Exception:
        pass



from contextlib import contextmanager

@contextmanager
def mac(iface, mac_addr):
    """
        This allows to make some action with a spoofed MAC address then reset it to its real value
        with mac(iface, mac_addr):
            ...
    """
    try:
        spoof_mac(iface, mac_addr)
        yield
    finally:
        reset_mac(iface)

def with_mac(iface, mac_addr):
    """
        You can use it to wrap/decorate a function so that the function will spoof the MAC address while it runs

        @with_mac(iface, mac_addr)
        def myfunc(...):
            ...

        You can also do any action that you could do with a decorator, as using it dynamically:

        wrapped_func = with_mac(iface, mac_addr)(my_func)
    """
    def inner(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            with mac(iface, mac_addr):
                f(*args, **kwargs)
        return wrapper
    return inner


def get_fake_channel(channel):
    """
        Get the channel to use from the real one.
        Default to 1 if no channel is provided or if the value is invalid.
        Otherwise, the channel used is 6 canal away from the original one
    """
    if not channel or channel < 1 or channel > 14:
        return DEFAULT_CHANNEL
    if channel <= 8:
        return channel + 6
    else:
        return channel - 6
    return None

def change_channel(interface, channel):
    """
        Change the channel of the interface (this function is vulnerable to injections)
    """
    os.system("iw dev %s set channel %d" %(interface, channel))

def pkt2ap(pkt):
    """
        if the packet is NOT a beacon trame, return None
        Otherwise, create an AP dataclass with the beacon data
    """
    if not pkt.haslayer(Dot11Beacon):
        return None
    bssid = pkt[Dot11].addr2
    ssid = pkt[Dot11Elt].info.decode()
    try:
        rsn = pkt[Dot11EltRSN].info
    except:
        rsn = default_rsn()
    try:
        dbm_signal = pkt.dBm_AntSignal
    except:
        dbm_signal = "N/A"
    stats = pkt[Dot11Beacon].network_stats()
    channel = stats.get("channel")
    crypto = stats.get("crypto")

    return AP(bssid, ssid, channel, crypto, dbm_signal, rsn)


def pkt_probreq_2ap(pkt):
    """
        if the packet is NOT a probe request, return None
        Otherwise, create an AP dataclass matching the probe request
    """
    if not pkt.haslayer(Dot11ProbeReq):
        return None
    bssid = pkt[Dot11].addr2
    ssid = pkt[Dot11Elt].info.decode()
    rsn = _default_rsn()
    try:
        dbm_signal = pkt.dBm_AntSignal
    except:
        dbm_signal = "N/A"
    stats = pkt[Dot11ProbeReq].network_stats()
    channel = stats.get("channel")
    crypto = stats.get("crypto")

    return AP(bssid, ssid, channel, crypto, dbm_signal, rsn)

# END utilities definition
# ====================================================================================================
# START of beacon spoofing

def _default_rsn():
    """
        Raw default RSN value
    """
    return (
        '\x01\x00'              # RSN Version 1
        '\x00\x0f\xac\x02'      # Group Cipher Suite : 00-0f-ac TKIP
        '\x02\x00'              # 2 Pairwise Cipher Suites (next two lines)
        '\x00\x0f\xac\x04'      # AES Cipher
        '\x00\x0f\xac\x02'      # TKIP Cipher
        '\x01\x00'              # 1 Authentication Key Managment Suite (line below)
        '\x00\x0f\xac\x02'      # Pre-Shared Key
        '\x00\x00'              # RSN Capabilities (no extra capabilities)
    )
def default_rsn():
    """
        Default RSN value
    """
    return Dot11Elt(ID='RSNinfo', info=_default_rsn())

def _beacon(net_ssid, src_mac_addr, ap_mac_addr, iface=DEFAULT_IFACE, inter=0.100, rsn=None, channel=None):
    """
        This function will emit beacon trames
    """
    dot11 = Dot11(
        type=0,                         # To indicate the frame is a management frame (type 0).
        subtype=8,                      # To indicate the management frames subtype is a beacon (type 8).
        addr1="ff:ff:ff:ff:ff:ff",      # Destination MAC address.  => We need to broadcast
        addr2=src_mac_addr,             # Source MAC address of sender.
        addr3=ap_mac_addr,              # MAC address of Access Point.
    )
    beacon = Dot11Beacon(
        cap='ESS+privacy'
    )
    essid = Dot11Elt(ID='SSID',info=net_ssid, len=len(net_ssid))
    if rsn is None:
        rsn = default_rsn()
    elif isinstance(rsn, str):
        rsn = Dot11Elt(ID='RSNinfo', info=rsn)


    if channel is not None:
        new_essid = Dot11Elt(ID="DSset", info=chr(channel))
        frame = RadioTap()/dot11/beacon/essid/new_essid/rsn
    else:
        frame = RadioTap()/dot11/beacon/essid/rsn


    # frame.show()
    # print("\nHexDump of frame:")
    # hexdump(frame)
    input("\nPress enter to start\n")
    sendp(frame, iface=iface, inter=inter, loop=1)

def beacon(net_ssid, src_mac_addr, ap_mac_addr, iface=DEFAULT_IFACE, inter=0.100, channel=None, spoof_mac=False):
    """
        This function will emit beacon trames, it can also spoof the MAC address
    """
    func = partial(_beacon, net_ssid, src_mac_addr, ap_mac_addr, iface=iface, inter=inter, channel=channel)
    if spoof_mac:
        func = with_mac(iface, ap_mac_addr)(func)
    return func()

# END of beacon spoofing
# ====================================================================================================
# START definition of AP dataclass

from dataclasses import dataclass
@dataclass
class AP:
    """
        Representation of an AP
    """
    bssid: str
    ssid: str
    channel: str
    crypto: str
    power: str
    rsn: str
    def __hash__(self) -> int:
        return hash(self.bssid)
    def __eq__(self, other) -> bool:
        return self.bssid == other.bssid
    def spoof(self, iface=DEFAULT_IFACE, inter=0.100, ssid=None, bssid=None, randmac=False, spoof_mac=False):
        channel = get_fake_channel(self.channel)
        ssid = ssid or self.ssid
        bssid = bssid or self.bssid
        if randmac:
            bssid = RandMAC()
        print("Spoofing: {} ({}) -> {}({})".format(self.ssid, self.bssid, ssid, bssid))
        return beacon(ssid, bssid, bssid, iface=iface, inter=inter, channel=channel, spoof_mac=spoof_mac)

# END definition of AP dataclass
# ====================================================================================================
# START of AP selection

from scapy.all import (
    sniff,
    Dot11EltRSN,
)
import os


# Lots of formatting variables, don't worry about those
INDEX_COL_WIDTH = 6
BSSID_COL_WIDTH = 18
SSID_COL_WIDTH = 25
CHANNEL_COL_WIDTH = 8
CRYPTO_COL_WIDTH = 25
POWER_COL_WIDTH = 12
ARRAY_WIDTH = INDEX_COL_WIDTH + BSSID_COL_WIDTH + SSID_COL_WIDTH + CHANNEL_COL_WIDTH + CRYPTO_COL_WIDTH + POWER_COL_WIDTH + 17

def _print_ap_table_line(index, ap):
    print(
        str(index).ljust(INDEX_COL_WIDTH, ' '), "|",
        ap.bssid.ljust(BSSID_COL_WIDTH, ' '),"|",
        ap.ssid.ljust(SSID_COL_WIDTH, ' '),"|",
        str(ap.channel).ljust(CHANNEL_COL_WIDTH, ' '),"|",
        str(ap.crypto).ljust(CRYPTO_COL_WIDTH, ' '),"|",
        str(ap.power).ljust(POWER_COL_WIDTH, ' '),"|"
    )

def display_ap_table(ap_list):
    _print_ap_table_line(
        "", AP(
            "BSSID",
            "SSID",
            "Channel",
            "Crypto",
            "Power [dBm]",
            "",  # RSN
        )
    )
    print('-' * ARRAY_WIDTH)
    for index, ap in enumerate(ap_list):
        _print_ap_table_line(index, ap)

def ask_ap_to_spoof(ap_list):
    print("Which SSID do you want to spoof ? ")
    display_ap_table(ap_list)
    chosen = -1
    while chosen not in range(0, len(ap_list)):
        try:
            chosen = int(input("Choose SSID: "))
        except Exception:
            chosen = -1
    return ap_list[chosen]

# END of AP selection
# ====================================================================================================
# START of AP discovery

def find_ap_by_beacon_count(iface=DEFAULT_IFACE, count=10, channels=None, **_):
    AP_LIST = set()

    # Callback function to use on each sniffed packet
    # Source: https://www.thepythoncode.com/article/building-wifi-scanner-in-python-scapy
    def callback(pkt, AP_LIST=AP_LIST):
        ap = pkt2ap(pkt)
        if ap is not None:
            AP_LIST.add(ap)

    # Sniff only as long as packet_count
    channels = channels or list(range(1, 12))
    for channel in channels:
        print(f'Scanning channel {channel} for SSIDs')
        sniff(iface=iface, prn = callback, count = count)
        channel = change_channel(iface, channel)
    return list(AP_LIST)

def find_ap_by_beacon_timeout(iface=DEFAULT_IFACE, timeout=1, channels=None, **_):
    AP_LIST = set()

    # Sniff only as long as packet_count
    channels = channels or list(range(1, 12))
    for channel in channels:
        print(f'Scanning channel {channel} for SSIDs')
        packets = sniff(iface=iface, timeout=timeout)
        AP_LIST.update({
            ap for ap in (pkt2ap(p) for p in packets)
            if ap is not None
        })
        channel = change_channel(iface, channel)
    return list(AP_LIST)

# find_ap = find_ap_by_count
find_ap = find_ap_by_beacon_timeout

def find_ap_by_probe_request_timeout(iface=DEFAULT_IFACE, timeout=1, channels=None, **_):
    AP_LIST = set()

    # Sniff only as long as packet_count
    channels = channels or list(range(1, 12))
    for channel in channels:
        print(f'Scanning channel {channel} for SSIDs')
        packets = sniff(iface=iface, timeout=timeout)
        AP_LIST.update({
            ap for ap in (pkt_probreq_2ap(p) for p in packets)
            if ap is not None
        })
        channel = change_channel(iface, channel)
    return list(AP_LIST)

# END of AP discovery
# ====================================================================================================
