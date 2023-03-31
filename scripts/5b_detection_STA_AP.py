from scapy.all import *
from config import WIFI_INTERFACE_NAME


knownAssociations = []


def packet_handler(packet):
    # taken from https://stackoverflow.com/questions/52981542/python-scapy-distinguish-between-acesspoint-to-station

    # search only in data frame
    isDataFrame = packet.haslayer(Dot11) and packet.type == 2

    if isDataFrame:
        DS = packet.FCfield & 0x3
        toDS = DS & 0x01 != 0
        fromDS = DS & 0x2 != 0

        # from STA to AP
        if toDS and not fromDS:
            sta = packet.addr2
            ap = packet.addr1

        # from AP to STA
        if not toDS and fromDS:
            sta = packet.addr1
            ap = packet.addr2

        association = f"{sta}\t{ap}"
        if association not in knownAssociations:
            print(association)
            knownAssociations.append(association)


if __name__ == "__main__":
    print("Sniffing for all STAs connected to APs")
    print("STA \t\t\t AP")
    sniff(iface=WIFI_INTERFACE_NAME, prn=packet_handler)
