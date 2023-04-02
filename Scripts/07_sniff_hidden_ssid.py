import os
import sys
from scapy.all import *
from tabulate import tabulate


# Initialize an empty set to store hidden SSIDs
hidden_ssids = set()

# Set the mode of a network interface (e.g., managed or monitor mode)
def set_interface_mode(interface, mode):
    # Bring the interface down
    os.system(f"sudo ip link set {interface} down")
    # Set the mode of the interface
    result = os.system(f"sudo iw {interface} set type {mode}")
    # Check if the mode change was successful
    if result != 0:
        print(f"Failed to set {interface} to {mode} mode.")
    # Bring the interface up
    os.system(f"sudo ip link set {interface} up")

# Set the network interface to monitor mode
def set_monitor_mode(interface):
    set_interface_mode(interface, "monitor")

# Set the network interface to managed mode
def set_managed_mode(interface):
    set_interface_mode(interface, "managed")

# Callback function to handle captured packets
def packet_handler(pkt):
    # Check if the packet is a Probe Response or Association Request frame
    if pkt.haslayer(Dot11ProbeResp) or pkt.haslayer(Dot11AssoReq):
        # Extract and decode the SSID from the packet
        ssid = pkt[Dot11Elt].info.decode("utf-8", "ignore")
        # If the SSID is not already in the hidden_ssids set, add it and print the SSID
        if ssid not in hidden_ssids:
            hidden_ssids.add(ssid)
            print(f"Found hidden SSID: {ssid}")

def main():
    # Check if the script was called with the correct number of arguments
    if len(sys.argv) != 2:
        print("Usage: python3 hidden_ssid_sniffer.py [monitor_interface]")
        sys.exit(1)

    # Get the network interface from the command line argument
    monitor_interface = sys.argv[1]

    # Set the network interface to monitor mode
    set_monitor_mode(monitor_interface)

    # Sleep for 2 seconds to allow the interface to properly switch to monitor mode
    time.sleep(2)

    # Start sniffing for hidden SSIDs
    print("Sniffing for hidden SSIDs...")
    try:
        # Start sniffing and pass captured packets to the packet_handler function
        sniff(iface=monitor_interface, prn=packet_handler, timeout=10)
    except KeyboardInterrupt:
        # Handle the KeyboardInterrupt (Ctrl+C) and print the results
        print("\nStopped sniffing.")
        print("Hidden SSIDs found:")
        for ssid in hidden_ssids:
            print(f"- {ssid}")

    # Print the results
    print("\nSniffing completed.")
    print("Hidden SSIDs found:")
    
    # Create a table with the hidden SSIDs
    table_data = [[i + 1, ssid] for i, ssid in enumerate(hidden_ssids)]
    table_headers = ["#", "SSID"]
    table = tabulate(table_data, headers=table_headers, tablefmt="pretty")
    
    # Print the table
    print(table)

if __name__ == "__main__":
    main()
