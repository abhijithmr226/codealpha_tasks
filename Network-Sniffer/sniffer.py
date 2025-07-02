import scapy.all as scapy
import psutil
import socket
import threading
import time
import sys
import platform
from prettytable import PrettyTable
from colorama import Fore, Style
from scapy.layers.inet import IP, TCP, UDP, ICMP

# OS detection
IS_WINDOWS = platform.system().lower() == "windows"

if IS_WINDOWS:
    import msvcrt
else:
    import tty
    import termios
    import select

# Get MAC Address of interface
def get_current_mac(interface):
    try:
        addrs = psutil.net_if_addrs()
        for addr in addrs.get(interface, []):
            if hasattr(socket, "AF_LINK") and addr.family == socket.AF_LINK:
                return addr.address
            elif str(addr.family).endswith("AF_PACKET"):
                return addr.address
        return "MAC Not Found"
    except Exception as e:
        return f"Error: {e}"

# Get IP Address of interface
def get_current_ip(interface):
    try:
        addrs = psutil.net_if_addrs()
        for addr in addrs.get(interface, []):
            if addr.family == socket.AF_INET:
                return addr.address
        return "No IP Found"
    except Exception as e:
        return f"Error: {e}"

# Display interfaces
def ip_table():
    addrs = psutil.net_if_addrs()
    t = PrettyTable([f"{Fore.GREEN}Index", "Interface", "MAC Address", f"IP Address{Style.RESET_ALL}"])
    interfaces = list(addrs.keys())
    for idx, iface in enumerate(interfaces):
        mac = get_current_mac(iface)
        ip = get_current_ip(iface)
        t.add_row([idx, iface, mac, ip])
    print(t)
    return interfaces

# Packet callback
def packet_callback(packet):
    packet_details = f"{Fore.CYAN}Packet Details:{Style.RESET_ALL}\n"

    if IP in packet:
        packet_details += f"{Fore.GREEN}IP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Source IP: {packet[IP].src} -> Destination IP: {packet[IP].dst}\n"
        packet_details += f"ID: {packet[IP].id} ; Version: {packet[IP].version} ; Length: {packet[IP].len} ; Flags: {packet[IP].flags}\n"
        packet_details += f"Protocol: {packet[IP].proto} ; TTL: {packet[IP].ttl} ; Checksum: {packet[IP].chksum}\n"

    if TCP in packet:
        packet_details += f"{Fore.YELLOW}TCP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Source Port: {packet[TCP].sport} -> Destination Port: {packet[TCP].dport}\n"
        packet_details += f"Seq #: {packet[TCP].seq} ; Ack #: {packet[TCP].ack} ; Window: {packet[TCP].window} ; Flags: {packet[TCP].flags}\n"

    if UDP in packet:
        packet_details += f"{Fore.YELLOW}UDP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Source Port: {packet[UDP].sport} -> Destination Port: {packet[UDP].dport}\n"

    if ICMP in packet:
        packet_details += f"{Fore.YELLOW}ICMP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Type: {packet[ICMP].type} ; Code: {packet[ICMP].code}\n"

    print(packet_details)

stop_sniffing = False

def sniff(interface):
    global stop_sniffing
    def stop_sniff(packet):
        return stop_sniffing
    scapy.sniff(iface=interface, prn=packet_callback, store=False, stop_filter=stop_sniff)

# Cross-platform keypress monitor
def monitor_keypress():
    global stop_sniffing
    print(f"{Fore.YELLOW}[*] Press 'q' to stop sniffing...{Style.RESET_ALL}")
    
    if IS_WINDOWS:
        while True:
            if msvcrt.kbhit():
                ch = msvcrt.getch().decode('utf-8').lower()
                if ch == 'q':
                    stop_sniffing = True
                    break
            if stop_sniffing:
                break
    else:
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while True:
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    ch = sys.stdin.read(1).lower()
                    if ch == 'q':
                        stop_sniffing = True
                        break
                if stop_sniffing:
                    break
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def main():
    global stop_sniffing
    print(f"{Fore.BLUE}Welcome To Packet Sniffer!{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[***] Please start ARP Spoofer before using this module [***]{Style.RESET_ALL}\n")

    try:
        interfaces = ip_table()
        if not interfaces:
            print(f"{Fore.RED}[!] No interfaces found.{Style.RESET_ALL}")
            return

        while True:
            try:
                selection = int(input("\n[*] Enter the index of the interface to sniff: "))
                if 0 <= selection < len(interfaces):
                    selected_iface = interfaces[selection]
                    break
                else:
                    print(f"{Fore.RED}Invalid index. Please try again.{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}Please enter a valid number.{Style.RESET_ALL}")

        print(f"\nSelected Interface: {Fore.CYAN}{selected_iface}{Style.RESET_ALL}")
        print(f"IP Address: {get_current_ip(selected_iface)}")
        print(f"MAC Address: {get_current_mac(selected_iface)}")
        print(f"\n{Fore.GREEN}[*] Sniffing Packets... Press 'q' to stop.{Style.RESET_ALL}\n")

        threading.Thread(target=monitor_keypress, daemon=True).start()
        sniff(selected_iface)

        print(f"{Fore.YELLOW}\n[*] Sniffing stopped.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
