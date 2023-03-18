#!/usr/bin/env python

from scapy.all import *
import sys
import argparse
import random


SSID_LENGTH = 12
ssids = []

# Function to generate a random SSID name
def generate_ssid():
    ssid_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'

    random_string = ''.join(random.choice(ssid_alphabet) for i in range(SSID_LENGTH))

    return "WIFI_" + random_string

# Function to generate a random MAC address
# Source: https://stackoverflow.com/questions/8484877/mac-address-generator-in-python
def generate_mac():
    return "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),random.randint(0, 255),random.randint(0, 255))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--list")

    args = parser.parse_args()

    if args.list == None:
        print("No SSID name list specified. Using generated SSIDs")
        amount = 0

        while (amount == 0 or amount > 100):
            amount = int(input("Enter number of SSID to generate:"))

        for i in range(0,amount):
            ssids.append(generate_ssid())

        print(ssids)

        

if __name__ == "__main__":
    main()
