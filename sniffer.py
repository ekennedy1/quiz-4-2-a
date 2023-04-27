from scapy.all import *
from scapy.all import Ether, IP, TCP, sendp
import time


def main():
    """Driver function"""
    while True:
        print_menu()
        option = input('Choose a menu option: ')
        if option == '1':
            print("Creating and sending packets ...")
            # TODO
            number = input('How many packets? ')
            interval = input('How many seconds in between sending? ')
            send_pkt(number, interval)
        elif option == '2':
            print("Listening to all traffic to 8.8.4.4 for 1 minute ...")
            # TODO
            sniff(filter="dst 8.8.4.4", prn=print_pkt, timeout=60)
        elif option == '3':
            print("Listening continuously to only ping commands to 8.8.4.4 ...")
            # TODO
            sniff(filter="icmp and dst 8.8.4.4", prn=print_pkt, timeout=60)
        elif option == '4':
            print("Listening continuously to only outgoing telnet commands ...")
            # TODO
            sniff(filter="dst port 23", prn=print_pkt, timeout=60)
        elif option == '5':
            print("End")
            break
        else:
            print(f"\nInvalid entry\n")


def send_pkt(number, interval):
    """
    Send a custom packet with the following fields

    #### Ethernet layer
    - Source MAC address: 00:11:22:33:44:55
    - Destination MAC address: 55:44:33:22:11:00

    #### IP layer
    - Source address: 192.168.10.4
    - Destination address: 8.8.4.4
    - Protocol: TCP
    - TTL: 26

    #### TCP layer
    - Source port: 23
    - Destination port: 80

    #### Raw payload
    - Payload: "RISC-V Education: https://riscvedu.org/"
    """

    # TODO
    # Define the Ethernet frame
    eth = Ether(src='00:11:22:33:44:55', dst='55:44:33:22:11:00', type=0x0800)

    # Define the IP packet
    ip = IP(src='192.168.10.4', dst='8.8.4.4', proto='tcp', ttl = 26)

    # Define the TCP segment
    tcp = TCP(sport=23, dport=80)

    # Define the payload
    payload = b'RISC-V Education: https://riscvedu.org/'

    # Combine everything into a single packet
    packet = eth/ip/tcp/payload

    sendp(packet, count=int(number), inter=int(interval))

    pass


def print_pkt(packet):
    """ 
    Print Packet fields

    - Source IP
    - Destination IP
    - Protocol number
    - TTL
    - Length in bytes
    - Raw payload (if any)
    """

    # TODO
    
    print("Source IP:", packet[IP].src)
    print("Destination IP:", packet[IP].dst)
    print("Protocol:", packet[IP].proto)
    print("Packet TTL:", packet[IP].ttl)
    print("Packet Length:", packet[IP].len)
    print("Packet Payload:", packet[IP].load)    
    ##print(f"The packet full data is {packet.show()}")
    print("\n")
    
    pass


def print_menu():
    """Prints the menu of options"""
    print("*******************Main Menu*******************")
    print('1. Create and send packets')
    print('2. Listen to all traffic to 8.8.4.4 for 1 minute')
    print('3. Listen continuously to only ping commands to 8.8.4.4')
    print('4. Listen continuously to only outgoing telnet commands')
    print('5. Quit')
    print('***********************************************\n')


main()
