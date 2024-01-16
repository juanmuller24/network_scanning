Network Scanner Code Description

Overview

The Network Scanner is a Python application that combines Scapy and standard socket libraries to perform host discovery, port scanning, and OS fingerprinting. Below are the main features of the code:

main.py

Features:
Host Discovery:
Utilizes ARP requests to discover live hosts within a specified IP range.
Displays active hosts and initiates port scanning for each.
Port Scanning:
Scans open ports of a target using both Scapy and standard socket libraries.
Provides detailed information about open ports on active hosts.
OS Fingerprinting:
Performs OS fingerprinting based on ICMP packets.
Identifies the likely OS of each live host.
User-Friendly Menu:
Presents a menu interface for easy selection between host and port scanning.
Guides users through the process with clear prompts.
Usage:
Run main.py.
Choose between host scanning (1) or port scanning (2).
Enter the target IP address or hostname.
Specify port range details.
View results, including active hosts, open ports, and likely OS information.
scapy Directory

Features:
Scapy Integration:
Houses Scapy-related functions for ARP requests and OS fingerprinting.
Usage:
Functions in this directory are imported and utilized in main.py for specific tasks.
Security Considerations:

The code efficiently utilizes both Scapy and standard socket libraries for comprehensive network analysis.
Implements timeout settings for network operations to balance speed and accuracy.
This Network Scanner is a versatile tool for network administrators and security professionals, providing insights into live hosts, open ports, and potential vulnerabilities.
