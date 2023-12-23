#!/usr/bin/python3
'''
Darpan Katarya
This is a simple tool written in python for scanning an internal network 
'''

import os
import sys
from scapy.all import *


####################################
######### Main Function #########
####################################
#This is the starting point of the program
#It includes instructions on what this tool will do once a user exeutes this script
def main(): 

  argument_check()                                       # Check if the correct number and type of arguments have been provided
  interface = sys.argv[2]                                # Get the network interface from the command line arguments
  mode = sys.argv [3]                                    # Get the mode (active or passive) from the command line arguments
  #mode_check(mode)                                       # Check if the provided mode is valid (either active or passive)
  ip_address=get_interface_ip(interface)                 # Get the IP address of the specified network interface
  
  if mode == '-a' or mode == '--active':                 # If the mode is active...
     mode = 'Active'                                     # Set the mode to 'Active'
     active_scan(interface,mode, ip_address)             # Perform an active scan on the specified network interface
     print(f'\n\n[ |+_+| ] Active Scan completed ')      # Print a message indicating that the active scan has completed

  
  if mode == '-p' or mode == '--passive':                # If the mode is passive...
     mode = 'Passive'                                    # Set the mode to 'Passive'
     passive_scan(interface,mode)                        # Perform a passive scan on the specified network interface
     print(f'\n\n[ |+_+| ] Passive Scan completed ')     # Print a message indicating that the passive scan has completed



####################################
######### Help function #########
####################################
def help():
  print("\nUsage: net_recon.py <interface> <mode>")
  print("\nArguments:")
  print(" \n <interface>\t\tNetwork interface name (e.g., 'eth0')")
  print("  -i, --interface ")
  print(" \n <mode>\t\t\tMode of operation: 'active' or 'passive'")
  print("  -p, --passive \tEnable passive mode")
  print("  -a, --active  \tEnable active mode\n")
  print("\n Example : net_recon.py -i Interface1 -a\n")

#############################################
######### Argument length check #########
#############################################
#This function validates the length of the arguments specified by the user
# total length of arguments should be 4 and -i or --iface should be present in the specified arguments
def argument_check():                                      
    if '-i' not in sys.argv and '--iface' not in sys.argv:
        help()                                             # Call the help function which displays the help
        sys.exit(1)                                        # Exit the program

    if len(sys.argv) != 4 :                                # Check if the number of arguments is not equal to 4
        help()                                             # Call the help function which displays the help
        sys.exit(1)                                        # Exit the program

    valid_modes=['-a','-p','--active','--passive']         # valid_modes is a list which has the acceptable values for the mode
    mode = sys.argv[3]                                     # Assuming mode is the fourth argument
    if mode not in valid_modes:                            # Check if the mode provided by the user is not present in the list of valid modes 
        help()                                             # Call the help function which displays the help
        sys.exit(1)                                        # Exit the program

####################################
######### Interface check #########
####################################
def get_interface_ip(interface):                         # This function checks if the specified interface name is valid or not, accepts one argument 'interface'
    interfaces = get_if_list()                           # Get list of all network interfaces and store in variable 'interfaces'
    interface_to_check = interface                       # Store the interface specified by user in variable 'interfaces_to_check'
    for interface in interfaces:                         
        ip_address = get_if_addr(interface)              # Get the IP address associated with the interface
    if interface_to_check in interfaces:
        ip_address = get_if_addr(interface_to_check)                                   # Get the IP address associated with the interface
        return ip_address                                                              # Return the IP address that was found
    else:                                                                              # if the specified interface is not present in the list of interfaces
        print(f"\nThe specified interface {interface_to_check} does not exist!")       # Print that the specified interface does not exist
        help()                                                                         # Call the help function which displays the help
        sys.exit(1)                                                                    # Exit the program




####################################
######## Active scan #########
####################################
#this function performs the active scan by sending icmp packets
def active_scan(interface, mode, ip_address):                                                       # Function that performs active scanning, accepts three arguments, 'interface', 'mode' and 'ip_address'
    ip_parts = ip_address.split('.')                                                                # Split the 'ip_address' string into a list of strings at each '.'
    network_address = '.'.join(ip_parts[:-1]) + '.'                                                 # Join the first three parts of the 'ip_parts' list back into a string with '.' as the separator, and add a '.' at the end
    addresses = {}                                                                                  # Creates an empty dictionary to store IP and MAC address pairs

    for i in range(0, 256):                                                                             # Loop over the range from 0 to 255 (inclusive)
        ip = network_address + str(i)                                                                   # Construct an IP address by appending the current number to the network address
        icmp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=ip) / ICMP()                              # Create an ICMP echo request packet (commonly known as a "ping" packet) with the destination IP address set to 'ip' and the destination MAC address set to the broadcast address
        responses, unanswered = srp(icmp_packet, iface=interface, timeout=1, verbose=False)             # Send the ICMP packet on the network and wait for responses
        improved_display(interface, mode, addresses, None, i)                                           # Call the 'improved_display' function (not shown in this code snippet)
        if responses:                                                                                     # If there are any responses...
            for sent_packet, received_packet in responses:                                                # Iterate over each response
                addresses[received_packet[Ether].src] = received_packet[IP].src                           # Store the source IP and MAC addresses from the response in the 'addresses' dictionary
        else:                                                                                             # If there are no responses...
            print(f"|\t\t?\t\t|\t{ip}\t\t\t\t|")                                                          # Print a line indicating that the MAC address for this IP is unknown
            print('|-------------------------------------------------------------------------------|')
    improved_display(interface, mode, addresses, None, i)                                                 # Call the 'improved_display' function again after all requests have been sent to only display the MAC and IP of the host which responded


####################################
######### Passive Scan #########
####################################
#This is the function for passive scanning
def passive_scan(interface, mode):                                                       # Function that performs passive scanning, accepts two arguments 'interface' and 'mode'
    addresses = {}                                                                       # This dictionary will hold the IP and MAC address pairings
    packet_count = {}                                                                    # This dictionary will hold the total number of packets observed for each host
    def arp_display(pkt):                                                                # Define a function named 'arp_display' that takes a packet as an argument
        if pkt[ARP].op == 2:                                                             # Check if the ARP operation field in the packet is 2 (which means it's an ARP reply)
            if pkt[ARP].psrc in addresses:                                               # If the source IP address of the ARP packet is already in the 'addresses' dictionary
                if pkt[ARP].hwsrc not in addresses[pkt[ARP].psrc]:                       # And if the  MAC address of the ARP packet is not in the list of MAC addresses associated with the source IP address in the 'addresses' dictionary
                    addresses[pkt[ARP].psrc].append(pkt[ARP].hwsrc)                      # Then append the source MAC address to the list of MAC addresses associated with the source IP address in the 'addresses' dictionary
            else:                                                                        # If the source IP address of the ARP packet is not in the 'addresses' dictionary
                addresses[pkt[ARP].psrc] = [pkt[ARP].hwsrc]                              # Then add a new entry to the 'addresses' dictionary with the source IP address as the key and a list containing the source MAC address as the value
            packet_count[pkt[ARP].hwsrc] = packet_count.get(pkt[ARP].hwsrc, 0) + 1       # Increment the packet count for this host
        improved_display(interface, mode, addresses, packet_count)                       # Calls the improved display function
    os.system("trap 'signal_handler' 2")                                                 # Register signal handler for SIGINT (Ctrl+C)
    sniff(iface=interface, filter="arp", prn=arp_display, store=0)                       # Scapy's inbuilt function for packet sniffing



#################################################################################
########################### Improved Display ###########################
#################################################################################
def improved_display(interface, mode, addresses, packet_count=None,i=None):                                                              # Define a function named 'improved_display' that takes five arguments: 'interface', 'mode', 'addresses', 'packet_count', and 'i'
        os.system('clear')                                                                                                           # Clear the console output

        if mode == 'Passive':                                                                                                            # Check if the mode is 'Passive'
            #os.system('clear')                                                                                                           # Clear the console output
            print('|=======================================================================================|')
            print(f'|\t|Interface : {interface}|\t|\t|Mode : {mode}|\t|\t|Found : {sum(len(macs) for macs in addresses.values())}|\t|')  # Print the interface, mode, and the total number of MAC addresses found
            print('|=======================================================================================|')
            print("|\t|MAC|\t\t\t|\t|IP|\t\t\t|    |Host Activity|\t|")                                                                  # Print the headers for the MAC address, IP address, and host activity columns
            print('|=======================================================================================|')
                                                                                                                                         # Print all IP-MAC pairings, ordered by packet count
            for mac in sorted(packet_count, key=packet_count.get, reverse=True):                                                         # Iterate over the MAC addresses in the 'packet_count' dictionary, sorted in descending order by packet count
                for ip, macs in addresses.items():                                                                                       # Iterate over each IP-MAC pairing in the 'addresses' dictionary
                    if mac in macs:                                                                                                      # If the current MAC address is in the list of MAC addresses for the current IP address
                        print(f"|\t{mac if mac else '?'}\t|\t{ip if ip else '?'}\t\t|\t  {packet_count[mac]}\t\t|")                      # Print the MAC address, IP address, and packet count
                        print('|---------------------------------------------------------------------------------------|')

        if mode == 'Active':                                                                                      # Check if the mode is 'Active'
            print('|===============================================================================|')
            print(f'|\t|Interface : {interface}|\t|\t|Mode : {mode}\t|\t|Found : {len(addresses)}|\t|')           # Print the interface, mode, and total number of IP addresses found
            print('|===============================================================================|')
            print(f"|\t|MAC|\t\t\t|\t|IP|\t\t|    |Progress : {int(round((i+1)/256*100,1))}%|\t|")                # Print the headers for the MAC address, IP address, and progress columns
            print('|===============================================================================|')

                                                                                                                  # Print all IP-MAC pairings
            for mac, ip in addresses.items():                                                                     # Iterate over each IP-MAC pairing in the 'addresses' dictionary
                print(f"|\t{mac}\t|\t{ip}\t\t\t\t|")                                                              # Print the MAC address and IP address
                print('|-------------------------------------------------------------------------------|')
main()