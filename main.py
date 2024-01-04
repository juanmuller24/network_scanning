import socket
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, ICMP
from scapy.layers.l2 import ARP
from scapy.sendrecv import srp, sr1, sr
from datetime import datetime


def discover_hosts(ip_range):
    print("-" * 50)
    print("Scanning target:", ip_range)
    print("Time started:", datetime.now())
    print("-" * 50)
    # Create an ARP request packet to discover live hosts
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)

    # Send and receive ARP requests
    ans, _ = srp(arp_request, timeout=2, verbose=0)

    # Extract and return the list of live hosts
    live_hosts = [res[1][ARP].psrc for res in ans]
    return live_hosts


def scan_ports(target_ip, start_port, end_port):
    open_ports = []

    for port in range(start_port, end_port + 1):
        # Create a TCP packet to check if the port is open
        tcp_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")

        # Send and receive TCP packets
        response = sr1(tcp_packet, timeout=1, verbose=0)

        if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
            open_ports.append(port)

    return open_ports


def os_fingerprint(target_ip):
    # Create an ICMP packet for OS fingerprinting
    icmp_packet = IP(dst=target_ip) / ICMP()

    # Send and receive ICMP packets
    response, _ = sr(icmp_packet, timeout=1, verbose=0)

    if response:
        # Extract OS information from the response
        if response[0][1][ICMP].type == 0:
            return response[0][1][IP].ttl

    return None


def port_scan(target, start_port, end_port):
    try:
        ip = socket.gethostbyname(target)
        print("-" * 50)
        print("Scanning target:", ip)
        print("Time started:", datetime.now())
        print("-" * 50)

        for port in range(start_port, end_port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print("Port {}: Open".format(port))
            sock.close()

    except socket.gaierror:
        print("Hostname could not be resolved.")

    except socket.error:
        print("Could not connect to the server.")


if __name__ == "__main__":
    print('--- Menu ---')
    print('Host Scanning (1)')
    print('Port Scanning (2)')
    menu = int(input('Select from above:'))
    print('')
    if menu == 1:
        target = input("Enter the target IP address or hostname: ")
        start_port = int(input("Staring Port Number: "))
        end_port = int(input("Staring Port Number: "))
        live_hosts = discover_hosts(target)
        print(f"Active hosts are: {live_hosts}")
        for host in live_hosts:
            open_ports = scan_ports(host, start_port, end_port)
            if open_ports:
                print(f"Open ports on {host}: {open_ports}")

                # Perform OS fingerprinting for each live host
                ttl = os_fingerprint(host)
                if ttl is not None:
                    print(f"Likely OS on {host}: {ttl}")
            else:
                print(f"No open ports found on {host}")
                ttl = os_fingerprint(host)
                if ttl is not None:
                    print(f"Likely OS on {host}: {ttl}")
    elif menu == 2:
        target = input("Enter the target IP address or hostname: ")
        start_port = int(input("Start Port Number: "))
        end_port = int(input("End Port Number: "))
        port_scan(target, start_port, end_port)
    elif menu is not [1, 2]:
        print('Not valid selection')
