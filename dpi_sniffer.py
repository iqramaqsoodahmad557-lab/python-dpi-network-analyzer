from scapy.all import *
from scapy.layers.inet import IP
from scapy.packet import Raw
import socket
from colorama import Fore, init

# initialize colorama
init()

# list of suspicious IPs (example real public IPs often used in scans)
suspicious_ips = [
    "185.199.110.153",
    "45.33.32.156",
    "103.21.244.0"
]

# function to convert IP to domain name
def get_domain(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip


def process_packet(packet):

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        domain = get_domain(dst_ip)

        print(Fore.CYAN + f"\nSource: {src_ip}  -->  Destination: {domain}")

        # suspicious IP detection
        if src_ip in suspicious_ips:
            print(Fore.RED + f"⚠ ALERT: Suspicious IP detected: {src_ip}")

        # save packets to log file
        with open("packets_log.txt", "a") as f:
            f.write(f"{src_ip} -> {dst_ip}\n")

    if packet.haslayer(Raw):
        payload = packet[Raw].load

        try:
            data = payload.decode(errors="ignore")

            if "HTTP" in data:
                print(Fore.GREEN + "HTTP Traffic Detected")
                print(data[:200])

            if "DNS" in data:
                print(Fore.YELLOW + "DNS Traffic Detected")

        except:
            pass


print(Fore.BLUE + "Starting Deep Packet Inspection Sniffer...")

sniff(prn=process_packet, store=False)
