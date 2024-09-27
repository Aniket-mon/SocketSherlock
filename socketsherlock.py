import sys
import socket
from typing import List, Tuple, Dict, Generator
import ipaddress
from prettytable import PrettyTable
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import json

# MAKE IT COOL
print(r"""
 ____             _        _   ____  _                _            _    
/ ___|  ___   ___| | _____| |_/ ___|| |__   ___ _ __ | | ___   ___| | __
\___ \ / _ \ / __| |/ / _ \ __\___ \| '_ \ / _ \ '__|| |/ _ \ / __| |/ /
 ___) | (_) | (__|   <  __/ |_ ___) | | | |  __/ |   | | (_) | (__|   < 
|____/ \___/ \___|_|\_\___|\__|____/|_| |_|\___|_|   |_|\___/ \___|_|\_\
                                                                        
""")

print("Welcome to SocketSherlock - Your Port Investigation Tool!")
print("""
For more information about the tool, use: python socketsherlock.py -h
""")

# Store all the ports and their services
PORT_SERVICES = {
    7: "Echo", 9: "Discard", 13: "Daytime", 17: "QOTD", 19: "CharGen",
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    37: "Time", 42: "WINS", 49: "TACACS", 53: "DNS", 67: "DHCP/BOOTP",
    68: "DHCP/BOOTP", 69: "TFTP", 79: "Finger", 80: "HTTP", 88: "Kerberos",
    102: "MS Exchange", 110: "POP3", 111: "RPC", 119: "NNTP", 123: "NTP",
    135: "Microsoft RPC", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 162: "SNMP", 177: "XDMCP", 179: "BGP",
    194: "IRC", 201: "AppleTalk", 264: "BGMP", 318: "TSP", 381: "HP Openview",
    383: "HP Openview", 389: "LDAP", 411: "Direct Connect", 412: "Direct Connect",
    427: "SLP", 443: "HTTPS", 445: "Microsoft-DS", 464: "Kerberos", 465: "SMTPS",
    500: "ISAKMP", 512: "rexec", 513: "rlogin", 514: "syslog", 515: "LPD/LPR",
    520: "RIP", 521: "RIPng (IPv6)", 540: "UUCP", 546: "DHCPv6", 547: "DHCPv6",
    554: "RTSP", 560: "rmonitor", 563: "NNTP over SSL", 587: "SMTP", 591: "FileMaker",
    593: "Microsoft DCOM", 631: "Internet Printing Protocol", 636: "LDAP over SSL",
    639: "MSDP", 646: "LDP", 691: "MS Exchange", 860: "iSCSI", 873: "rsync",
    902: "VMware Server", 989: "FTP over SSL", 990: "FTP over SSL", 993: "IMAPS",
    995: "POP3S", 1025: "Microsoft RPC", 1026: "Windows Messenger", 1027: "Windows Messenger",
    1028: "Windows Messenger", 1029: "Windows Messenger", 1080: "SOCKS Proxy",
    1099: "rmiregistry", 1194: "OpenVPN", 1214: "Kazaa", 1241: "Nessus",
    1433: "Microsoft SQL Server", 1434: "Microsoft SQL Monitor", 1512: "WINS",
    1589: "Cisco VQP", 1701: "L2TP", 1723: "PPTP", 1725: "Steam",
    1741: "CiscoWorks 2000", 1755: "MS Media Server", 1812: "RADIUS", 1813: "RADIUS",
    1863: "MSN", 1900: "UPnP", 2000: "Cisco SCCP", 2002: "Cisco ACS",
    2049: "NFS", 2082: "cPanel", 2083: "cPanel SSL", 2100: "Oracle XDB",
    2121: "ccproxy-ftp", 2222: "DirectAdmin", 2302: "Halo", 2483: "Oracle DB",
    2484: "Oracle DB SSL", 2745: "Bagle.H", 2967: "Symantec AV", 3050: "Interbase DB",
    3074: "XBOX Live", 3124: "HTTP Proxy", 3128: "HTTP Proxy", 3222: "GLBP",
    3260: "iSCSI Target", 3306: "MySQL", 3389: "RDP", 3689: "iTunes",
    3690: "Subversion", 3724: "World of Warcraft", 3784: "Ventrilo", 3785: "Ventrilo",
    4333: "mSQL", 4444: "Blaster", 4664: "Google Desktop", 4672: "eMule",
    4899: "Radmin", 5000: "UPnP", 5001: "Slingbox", 5004: "RTP", 5005: "RTP",
    5050: "Yahoo! Messenger", 5060: "SIP", 5190: "AIM/ICQ", 5222: "XMPP/Jabber",
    5223: "XMPP/Jabber SSL", 5432: "PostgreSQL", 5500: "VNC Server", 5554: "Sasser",
    5631: "pcAnywhere", 5632: "pcAnywhere", 5800: "VNC over HTTP", 5900: "VNC Server",
    6000: "X11", 6001: "X11", 6112: "Battle.net", 6129: "DameWare", 6257: "WinMX",
    6346: "Gnutella", 6347: "Gnutella", 6881: "BitTorrent", 6969: "BitTorrent",
    7212: "GhostSurf", 7648: "CU-SeeMe", 8000: "Internet Radio", 8080: "HTTP-Proxy",
    8086: "Kaspersky AV", 8087: "Kaspersky AV", 8200: "VMware Server",
    8500: "Adobe ColdFusion", 8767: "TeamSpeak", 8866: "Bagle.B", 9100: "HP JetDirect",
    9101: "Bacula", 9119: "MXit", 9800: "WebDAV", 9898: "Dabber", 9988: "Rbot/Spybot",
    9999: "Abyss", 10000: "Webmin", 11371: "OpenPGP", 12035: "Second Life",
    12345: "NetBus", 13720: "NetBackup", 14567: "Battlefield", 15118: "Dipnet/Oddbob",
    19226: "AdminSecure", 19638: "Ensim", 20000: "Usermin", 24800: "Synergy",
    25999: "Xfire", 27015: "Half-Life", 27374: "Sub7", 28960: "Call of Duty",
    31337: "Elite", 33434: "traceroute"
}

def scan_port(ip_address: str, port: int, timeout: float = 1.0) -> Tuple[int, str, str, str]:
    service = PORT_SERVICES.get(port, "Unknown")
    try:
        with socket.create_connection((ip_address, port), timeout=timeout):
            return port, "open", service, ip_address
    except (socket.timeout, ConnectionRefusedError):
        return port, "closed", service, ip_address
    except Exception as e:
        return port, f"error: {str(e)}", service, ip_address

def scan(target: str, ports: List[int], timeout: float = 1.0) -> Generator[Tuple[int, str, str, str], None, None]:
    print(f'\nStarting scan for {target}')
    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(scan_port, target, port, timeout): port for port in ports}
        for future in tqdm(as_completed(future_to_port), total=len(ports), desc="Scanning", unit="port"):
            result = future.result()
            yield result

def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False

def parse_port_range(port_input):
    if port_input is None:
        return list(range(1, 1000))  # Default to scan ports 1-1000 if no ports are specified
    
    try:
        if '-' in port_input:
            start, end = map(int, port_input.split('-'))
            if 1 <= start < end <= 65535:
                return list(range(start, end + 1))
        else:
            ports = [int(p.strip()) for p in port_input.split(',')]
            if all(1 <= p <= 65535 for p in ports):
                return ports
    except ValueError:
        raise ValueError("Please enter valid port numbers")

def parse_arguments():
    parser = argparse.ArgumentParser(description="SocketSherlock - Your Port Investigation Tool!", add_help=False)
    parser.add_argument("targets", nargs='?', help="IP addresses to scan (comma-separated)")
    parser.add_argument("-p", "--ports", help="Port range to scan (e.g., 1-1000)", default="1-1000")
    parser.add_argument("-t", "--timeout", type=float, help="Timeout for each connection attempt", default=1.0)
    parser.add_argument("-o", "--output", help="Output file for JSON results")
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")
    
    args = parser.parse_args()
    
    if args.help:
        print_help_menu()
        sys.exit(0)
    
    return args

def main():
    args = parse_arguments()
    
    if not args.targets and not ('-h' in sys.argv or '--help' in sys.argv):
        print("Error: the following arguments are required: targets")
        print_help_menu()
        return
    
    targets = [ip.strip() for ip in args.targets.split(',') if validate_ip(ip.strip())]
    if not targets:
        print("[!] No valid IP addresses provided.")
        return

    ports = parse_port_range(args.ports)

    all_results = {}
    for ip_addr in targets:
        results = list(scan(ip_addr, ports, args.timeout))
        display_results(ip_addr, results)
        all_results[ip_addr] = results

    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(all_results, f, indent=2)
            print(f"\nResults saved to {args.output}")
        except IOError as e:
            print(f"Error writing to output file: {e}")

    print("\nScan complete.")

def print_help_menu():
    table = PrettyTable()
    table.field_names = ["Argument", "Description"]
    table.align["Argument"] = "l"
    table.align["Description"] = "l"
    table.max_width["Description"] = 50

    table.add_row(["targets", "IP addresses to scan (comma-separated)"])
    table.add_row(["-p, --ports", "Port range to scan (e.g., 1-1000 or 80,443,8080)"])
    table.add_row(["-t, --timeout", "Timeout for each port scan (default: 1.0s)"])
    table.add_row(["-h, --help", "Show this help message and exit"])

    print("SocketSherlock - Your Port Investigation Tool")
    print("\nUsage: python socketsherlock.py target [argument]")
    print("\nArguments:")
    print(table)

    print("\nExamples:")
    print("  python socketsherlock.py 192.168.1.1")
    print("  python socketsherlock.py 192.168.1.1,10.0.0.1 -p 80,443,8080")
    print("  python socketsherlock.py 192.168.1.1 -p 1-1000 -t 0.5")
    print("\nFor more information, visit: https://github.com/Aniket-mon/socketsherlock")

def display_results(ip_addr, results):
    print(f"\nScan results for {ip_addr}:")
    table = PrettyTable()
    table.field_names = ["PORT", "STATE", "SERVICE"]
    table.align = "l"
    
    sorted_results = sorted(results, key=lambda x: x[0])
    open_ports_found = False
    for port, state, service, _ in sorted_results:
        if state == "open":
            table.add_row([port, state, service])
            open_ports_found = True
    
    if open_ports_found:
        print(table)
    else:
        print("No open ports found.")

if __name__ == "__main__":
    main()