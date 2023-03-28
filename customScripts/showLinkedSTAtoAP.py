from scapy.all import *

# Create an empty list to store the MAC addresses of stations and APs
listStationsAPs = []

# Define a function to show the stations that are linked to an AP
def showStationsLinked(pkt):
    # We look for type 2, which are data frames, this way we know the station is linked to an AP.
    if pkt.type == 2:
        # Filters the broadcasts out since we only want communications between a STA and AP and vice-versa. Also addr3 can't be null
        if pkt.addr1 != "ff:ff:ff:ff:ff:ff" and pkt.addr2 != "ff:ff:ff:ff:ff:ff" and pkt.addr3 is not None:
            # Determine the MAC addresses of the station and AP
            if pkt.addr1 != pkt.addr3:
                link = (pkt.addr1, pkt.addr3)
            else:
                link = (pkt.addr2, pkt.addr3)
            
            # If the link between the station and the AP does not already exist, add it to the list and display it
            if link not in listStationsAPs:
                listStationsAPs.append(link)
                print(link[0] + " \t\t " + link[1]) # link[0] = station's MAC, link[1] = AP's MAC

# Main function
if __name__ == '__main__':
    print("\nSTAs                             APs")
    # Start sniffing packets on the specified interface and call the showStationsLinked function for each packet
    sniff(iface="wlan0", prn=showStationsLinked)
