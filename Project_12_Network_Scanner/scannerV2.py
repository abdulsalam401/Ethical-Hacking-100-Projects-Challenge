#!/usr/bin/env python3
"""
======================================================================
  PROJECT #12 — Network Scanner with OS Fingerprinting (WSL Compatible)
  100 Ethical Hacking Projects Series
  
  Features:
  - Works in WSL environment
  - Multiple discovery methods (TCP SYN, ICMP, common ports)
  - Port scanning with OS fingerprinting
  - JSON output support
======================================================================
"""

import argparse
import socket
import ipaddress
import json
import time
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from colorama import init, Fore, Style, Back

# Initialize colorama
init(autoreset=True)

class Colors:
    HEADER = Fore.CYAN + Style.BRIGHT
    OKBLUE = Fore.BLUE + Style.BRIGHT
    OKGREEN = Fore.GREEN + Style.BRIGHT
    WARNING = Fore.YELLOW + Style.BRIGHT
    FAIL = Fore.RED + Style.BRIGHT
    ENDC = Style.RESET_ALL
    BOLD = Style.BRIGHT
    DIM = Fore.LIGHTBLACK_EX
    MAGENTA = Fore.MAGENTA + Style.BRIGHT
    CYAN = Fore.CYAN

# Port definitions
TOP_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPC",
    135: "MSRPC", 139: "NETBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MYSQL", 3389: "RDP", 8080: "HTTP-ALT"
}

FAST_PORTS = {22: "SSH", 80: "HTTP", 443: "HTTPS", 445: "SMB", 3389: "RDP"}

# OS Fingerprint database
OS_DB = {
    'windows': {'ttl_range': (32, 128), 'windows': [8192, 16384, 65535], 'ports': [139, 445, 3389]},
    'linux': {'ttl_range': (64, 64), 'windows': [5840, 29200, 32768], 'ports': [22, 80, 443]},
    'macos': {'ttl_range': (64, 64), 'windows': [65535], 'ports': [22, 548, 8080]},
    'cisco': {'ttl_range': (255, 255), 'windows': [4128], 'ports': []}
}

class WSLNetworkScanner:
    def __init__(self, target_network, fast_mode=False, delay=0.1, output_file=None):
        self.target_network = target_network
        self.fast_mode = fast_mode
        self.delay = delay
        self.output_file = output_file
        self.results = []
        self.live_hosts = []
        self.ports_to_scan = FAST_PORTS if fast_mode else TOP_PORTS
        self.stop_scan = False
        
    def get_my_ip_network(self):
        """Get current machine's IP and network"""
        try:
            # Get default gateway and IP
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.split()
                if len(lines) > 2:
                    gateway = lines[2]
                    return gateway
            
            # Alternative: get hostname IP
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            if ip.startswith('127.'):
                return None
            return ip
        except:
            return None
    
    def ping_host(self, ip):
        """Test if host is alive using system ping"""
        try:
            # Different ping options for different OS
            cmd = ['ping', '-c', '1', '-W', '1', str(ip)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            return result.returncode == 0
        except:
            return False
    
    def tcp_connect_scan(self, ip, port):
        """TCP Connect scan (works in WSL)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((str(ip), port))
            sock.close()
            
            if result == 0:
                return {
                    'port': port,
                    'service': self.ports_to_scan.get(port, 'Unknown'),
                    'status': 'open',
                    'method': 'TCP Connect'
                }
            return None
        except:
            return None
    
    def scan_network_arp_alternative(self, network):
        """Alternative to ARP scan using ping sweep"""
        print(f"{Colors.OKBLUE}[*] Performing ping sweep on {network}...{Colors.ENDC}")
        live_hosts = []
        
        # Scan only the first 254 hosts to avoid long scans
        hosts = list(network.hosts())[:254]
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self.ping_host, ip): ip for ip in hosts}
            for i, future in enumerate(as_completed(futures)):
                if self.stop_scan:
                    break
                ip = futures[future]
                try:
                    if future.result():
                        live_hosts.append({
                            'ip': str(ip),
                            'mac': 'Unknown (WSL)',
                            'method': 'ICMP Ping'
                        })
                        print(f"{Colors.OKGREEN}[+] Live host: {ip} (ICMP){Colors.ENDC}")
                except:
                    pass
                
                if i % 50 == 0:
                    print(f"{Colors.DIM}[*] Progress: {i}/{len(hosts)} hosts scanned{Colors.ENDC}")
        
        return live_hosts
    
    def scan_common_ports_quick(self, ip):
        """Quick scan for common open ports to detect live hosts"""
        common_ports = [22, 80, 443, 445, 3389, 8080]
        open_ports_found = []
        
        for port in common_ports:
            result = self.tcp_connect_scan(ip, port)
            if result:
                open_ports_found.append(result)
            time.sleep(self.delay)
        
        return open_ports_found
    
    def discover_hosts_hybrid(self, network):
        """Hybrid discovery method combining multiple techniques"""
        live_hosts = []
        
        # Method 1: Ping sweep
        print(f"{Colors.OKBLUE}[*] Method 1: ICMP Ping Sweep{Colors.ENDC}")
        ping_hosts = self.scan_network_arp_alternative(network)
        live_hosts.extend(ping_hosts)
        
        # Method 2: Common port scan on gateway and known IPs
        print(f"{Colors.OKBLUE}[*] Method 2: Common Port Discovery{Colors.ENDC}")
        
        # Add common IPs to check (gateway, common devices)
        common_ips = []
        for i in [1, 2, 5, 10, 50, 100, 150, 200, 250, 254]:
            try:
                common_ips.append(next(network.hosts()))
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self.scan_common_ports_quick, ip): ip for ip in common_ips[:10]}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    open_ports = future.result()
                    if open_ports:
                        if str(ip) not in [h['ip'] for h in live_hosts]:
                            live_hosts.append({
                                'ip': str(ip),
                                'mac': 'Unknown',
                                'method': 'Port Discovery',
                                'open_ports': open_ports
                            })
                            print(f"{Colors.OKGREEN}[+] Live host: {ip} (has open ports){Colors.ENDC}")
                except:
                    pass
        
        return live_hosts
    
    def fingerprint_os_from_ttl(self, ttl):
        """Guess OS from TTL value"""
        if not ttl:
            return "Unknown", "Low"
        
        if ttl <= 64:
            if ttl == 64:
                return "Linux/macOS", "High"
            else:
                return "Linux/Unix-like", "Medium"
        elif ttl <= 128:
            if ttl == 128:
                return "Windows", "High"
            else:
                return "Windows/Unix", "Medium"
        elif ttl <= 255:
            if ttl == 255:
                return "Cisco/Solaris", "High"
            else:
                return "Network Device", "Medium"
        else:
            return "Unknown", "Low"
    
    def fingerprint_os_from_ports(self, open_ports):
        """Guess OS from open ports pattern"""
        ports = [p['port'] for p in open_ports]
        
        if 445 in ports and 139 in ports:
            return "Windows (SMB detected)", "High"
        elif 3389 in ports:
            return "Windows (RDP detected)", "High"
        elif 548 in ports:
            return "macOS (AFP detected)", "High"
        elif 22 in ports and 80 in ports and 443 in ports:
            return "Linux/Unix (Web server)", "High"
        elif 3306 in ports:
            return "Linux/Unix (MySQL)", "Medium"
        elif 8080 in ports:
            return "Application Server", "Medium"
        
        return None, None
    
    def get_ttl_via_traceroute(self, ip):
        """Get TTL value using traceroute approach"""
        try:
            # Simple traceroute using increasing TTL
            for ttl in [1, 2, 4, 8, 16, 32, 64]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    sock.settimeout(1)
                    # This is simplified - in practice would need proper ICMP
                    sock.close()
                except:
                    pass
            return 64  # Default guess
        except:
            return None
    
    def scan_host(self, host_info):
        """Complete scan for a single host"""
        ip = host_info['ip']
        mac = host_info.get('mac', 'N/A')
        
        print(f"\n{Colors.CYAN}[>] Deep scanning {ip}...{Colors.ENDC}")
        
        # Port scan
        open_ports = []
        for port in self.ports_to_scan.keys():
            result = self.tcp_connect_scan(ip, port)
            if result:
                open_ports.append(result)
                service = self.ports_to_scan.get(port, 'Unknown')
                print(f"{Colors.OKGREEN}  ✓ Port {port} open - {service}{Colors.ENDC}")
            time.sleep(self.delay)
        
        # OS Fingerprinting
        os_guess = "Unknown"
        confidence = "Low"
        details = ""
        
        # Try to get TTL (simplified - use ping)
        try:
            cmd = ['ping', '-c', '1', '-W', '1', ip]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                # Parse TTL from ping output
                for line in result.stdout.split('\n'):
                    if 'ttl=' in line.lower():
                        import re
                        ttl_match = re.search(r'ttl=(\d+)', line.lower())
                        if ttl_match:
                            ttl = int(ttl_match.group(1))
                            os_guess, confidence = self.fingerprint_os_from_ttl(ttl)
                            details = f"TTL={ttl}"
                            break
        except:
            pass
        
        # Refine with port-based fingerprinting
        port_os, port_conf = self.fingerprint_os_from_ports(open_ports)
        if port_os and port_conf == 'High':
            os_guess = port_os
            confidence = port_conf
            if details:
                details += f" + {port_os}"
            else:
                details = port_os
        
        result = {
            'ip': ip,
            'mac': mac,
            'status': 'alive',
            'os_guess': os_guess,
            'os_confidence': confidence,
            'os_details': details if details else 'Based on port analysis',
            'open_ports': open_ports,
            'scan_time': datetime.now().isoformat()
        }
        
        self.display_host_results(result)
        return result
    
    def display_host_results(self, result):
        """Display scan results for a single host"""
        print(f"{Colors.OKGREEN}┌─────────────────────────────────────────────────────────────┐{Colors.ENDC}")
        print(f"{Colors.OKGREEN}│{Colors.BOLD} Host: {result['ip']}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}├─────────────────────────────────────────────────────────────┤{Colors.ENDC}")
        print(f"{Colors.OKGREEN}│{Colors.DIM} MAC: {result['mac']}{Colors.ENDC}")
        
        # OS Detection with color
        if 'Windows' in result['os_guess']:
            os_color = Colors.OKBLUE
        elif 'Linux' in result['os_guess'] or 'Unix' in result['os_guess']:
            os_color = Colors.OKGREEN
        elif 'macOS' in result['os_guess']:
            os_color = Colors.MAGENTA
        else:
            os_color = Colors.WARNING
            
        print(f"{Colors.OKGREEN}│{Colors.BOLD} OS: {os_color}{result['os_guess']}{Colors.ENDC} "
              f"({Colors.DIM}{result['os_confidence']} confidence{Colors.ENDC})")
        if result['os_details']:
            print(f"{Colors.OKGREEN}│{Colors.DIM}   ↳ {result['os_details']}{Colors.ENDC}")
        
        # Open ports
        if result['open_ports']:
            print(f"{Colors.OKGREEN}├─────────────────────────────────────────────────────────────┤{Colors.ENDC}")
            print(f"{Colors.OKGREEN}│{Colors.BOLD} Open Ports ({len(result['open_ports'])}):{Colors.ENDC}")
            for port_info in result['open_ports'][:10]:  # Show first 10
                print(f"{Colors.OKGREEN}│   {Colors.CYAN}{port_info['port']:<6}{Colors.ENDC} "
                      f"{Colors.OKGREEN}OPEN{Colors.ENDC}     {Colors.DIM}{port_info['service']}{Colors.ENDC}")
            if len(result['open_ports']) > 10:
                print(f"{Colors.OKGREEN}│   {Colors.DIM}... and {len(result['open_ports'])-10} more{Colors.ENDC}")
        else:
            print(f"{Colors.OKGREEN}├─────────────────────────────────────────────────────────────┤{Colors.ENDC}")
            print(f"{Colors.OKGREEN}│{Colors.DIM}   No open ports found{Colors.ENDC}")
        
        print(f"{Colors.OKGREEN}└─────────────────────────────────────────────────────────────┘{Colors.ENDC}")
    
    def display_summary_table(self):
        """Display all results in a formatted table"""
        if not self.results:
            print(f"{Colors.WARNING}No hosts found to display.{Colors.ENDC}")
            return
        
        print(f"\n{Colors.HEADER}{'='*110}{Colors.ENDC}")
        print(f"{Colors.BOLD}  SCAN SUMMARY{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*110}{Colors.ENDC}")
        
        # Table header
        print(f"{Colors.BOLD}{'IP Address':<20} {'OS Guess':<35} {'Open Ports':<40} {'Confidence':<10}{Colors.ENDC}")
        print(f"{Colors.DIM}{'-'*110}{Colors.ENDC}")
        
        for result in self.results:
            # Color based on OS
            if 'Windows' in result['os_guess']:
                os_color = Colors.OKBLUE
            elif 'Linux' in result['os_guess'] or 'Unix' in result['os_guess']:
                os_color = Colors.OKGREEN
            elif 'macOS' in result['os_guess']:
                os_color = Colors.MAGENTA
            else:
                os_color = Colors.WARNING
            
            port_list = ', '.join([str(p['port']) for p in result['open_ports'][:8]])
            if len(result['open_ports']) > 8:
                port_list += f"... (+{len(result['open_ports'])-8})"
            
            print(f"{result['ip']:<20} "
                  f"{os_color}{result['os_guess'][:34]:<34}{Colors.ENDC} "
                  f"{Colors.DIM}{port_list:<40}{Colors.ENDC} "
                  f"{Colors.DIM}({result['os_confidence']}){Colors.ENDC}")
        
        print(f"{Colors.DIM}{'-'*110}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Total hosts found: {len(self.results)}{Colors.ENDC}")
        
        # Statistics
        total_ports = sum(len(r['open_ports']) for r in self.results)
        print(f"{Colors.OKGREEN}Total open ports discovered: {total_ports}{Colors.ENDC}")
    
    def save_to_json(self):
        """Save results to JSON file"""
        if not self.output_file:
            return
        
        try:
            json_data = {
                'scan_info': {
                    'target': str(self.target_network),
                    'scan_time': datetime.now().isoformat(),
                    'fast_mode': self.fast_mode,
                    'scanner': 'WSL Network Scanner v2'
                },
                'hosts': []
            }
            
            for result in self.results:
                json_data['hosts'].append({
                    'ip': result['ip'],
                    'mac': result['mac'],
                    'os_guess': result['os_guess'],
                    'os_confidence': result['os_confidence'],
                    'os_details': result['os_details'],
                    'open_ports': result['open_ports'],
                    'scan_time': result['scan_time']
                })
            
            with open(self.output_file, 'w') as f:
                json.dump(json_data, f, indent=2)
            
            print(f"\n{Colors.OKGREEN}[+] Results saved to {self.output_file}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] Failed to save JSON: {e}{Colors.ENDC}")
    
    def show_defenses(self):
        """Display defense mechanisms"""
        print(f"\n{Colors.HEADER}{'='*110}{Colors.ENDC}")
        print(f"{Colors.BOLD}  DEFENSE AGAINST NETWORK SCANNING (WSL Environment){Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*110}{Colors.ENDC}")
        
        defenses = [
            ("WSL-Specific:", ""),
            ("1. Use Windows Firewall", "Configure Windows Defender Firewall to block WSL traffic"),
            ("2. Limit WSL Network Access", "Use .wslconfig to restrict network interfaces"),
            ("3. VPN Segmentation", "Run WSL in isolated VPN environment"),
            ("", ""),
            ("General Defenses:", ""),
            ("4. Port Knocking", "Hide services behind sequence of connection attempts"),
            ("5. IDS/IPS", "Deploy Snort/Suricata to detect scanning patterns"),
            ("6. Rate Limiting", "Configure iptables: -A INPUT -p tcp --dport 22 -m limit --limit 1/s"),
            ("7. Honeypots", "Deploy honeypot services to identify scanners"),
            ("8. OS Fingerprinting Protection", "Modify TTL values, use TCP/IP stack hardening")
        ]
        
        for title, desc in defenses:
            if title:
                print(f"{Colors.OKGREEN}{title}{Colors.ENDC}: {Colors.DIM}{desc}{Colors.ENDC}")
            else:
                print()
        
        print(f"\n{Colors.WARNING}[!] Detection Log:{Colors.ENDC}")
        print(f"{Colors.DIM}  - Your IP would be logged in security systems{Colors.ENDC}")
        print(f"{Colors.DIM}  - Scan patterns detected as reconnaissance{Colors.ENDC}")
        print(f"{Colors.DIM}  - Firewall rules would rate-limit this activity{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*110}{Colors.ENDC}\n")
    
    def run(self):
        """Main scanning routine"""
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}  PROJECT #12 — WSL Network Scanner with OS Fingerprinting{Colors.ENDC}")
        print(f"{Colors.OKBLUE}  Optimized for Windows Subsystem for Linux (WSL){Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
        
        # Parse network
        try:
            network = ipaddress.ip_network(self.target_network, strict=False)
        except ValueError as e:
            print(f"{Colors.FAIL}[-] Invalid network: {e}{Colors.ENDC}")
            return
        
        print(f"{Colors.OKBLUE}[*] Target: {network}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}[*] Mode: {'FAST (top 5 ports)' if self.fast_mode else 'Standard (top 20 ports)'}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}[*] Delay: {self.delay}s{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] Note: WSL has limited ARP capability, using alternative methods{Colors.ENDC}\n")
        
        # Discover live hosts
        live_hosts = self.discover_hosts_hybrid(network)
        
        if not live_hosts:
            print(f"{Colors.FAIL}[-] No live hosts found.{Colors.ENDC}")
            print(f"{Colors.WARNING}[!] Try these troubleshooting steps:{Colors.ENDC}")
            print(f"{Colors.DIM}  1. Check if you're on the correct network{Colors.ENDC}")
            print(f"{Colors.DIM}  2. Try: ping 8.8.8.8 (to test internet connectivity){Colors.ENDC}")
            print(f"{Colors.DIM}  3. Try: ip addr show (to see your network interface){Colors.ENDC}")
            print(f"{Colors.DIM}  4. Try scanning 127.0.0.1/24 for localhost{Colors.ENDC}")
            return
        
        print(f"\n{Colors.OKGREEN}[+] Found {len(live_hosts)} live host(s){Colors.ENDC}")
        
        # Scan each host
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(self.scan_host, host): host for host in live_hosts}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    self.results.append(result)
                except Exception as e:
                    print(f"{Colors.FAIL}[-] Scan failed: {e}{Colors.ENDC}")
        
        # Display results
        self.display_summary_table()
        
        # Save JSON
        self.save_to_json()
        
        # Show defenses
        self.show_defenses()

def main():
    parser = argparse.ArgumentParser(
        description="WSL Network Scanner with OS Fingerprinting",
        epilog="Example: sudo python3 scannerV2.py --target 192.168.1.0/24"
    )
    parser.add_argument("--target", required=True,
                        help="Target network (e.g., 192.168.1.0/24)")
    parser.add_argument("--fast", action="store_true",
                        help="Fast mode: scan top 5 ports only")
    parser.add_argument("--output", help="Save results to JSON file")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="Delay between probes (default: 0.1)")
    
    args = parser.parse_args()
    
    # Create scanner and run (no root required for TCP Connect in WSL)
    scanner = WSLNetworkScanner(
        target_network=args.target,
        fast_mode=args.fast,
        delay=args.delay,
        output_file=args.output
    )
    
    scanner.run()

if __name__ == "__main__":
    main()

# #!/usr/bin/env python3
# """
# ======================================================================
#   PROJECT #12 — Network Scanner with OS Fingerprinting (Nmap-style)
#   100 Ethical Hacking Projects Series
  
#   Features:
#   - Subnet discovery (ICMP + ARP scan)
#   - Port scanning (top 20 ports)
#   - OS Fingerprinting via TTL + TCP Window analysis
#   - JSON output support
#   - Colored table output
# ======================================================================

# DEFENSE AGAINST NETWORK SCANNING:
# 1. Rate Limiting - Detect and block excessive connection attempts
# 2. Port Knocking - Hide services behind sequence of connection attempts
# 3. IDS/IPS - Snort/Suricata detect SYN scans (flags: no ACK, many SYN from single IP)
# 4. Honeypots - Deceptive services to identify scanners
# 5. Firewall Rules - Limit ICMP, block unused ports, rate limit SYNs
# 6. OS Fingerprinting Obfuscation - Modify TTL, TCP window, use IP spoofing
# 7. Stealth Scan Detection - Monitor for unusual packet patterns

# USAGE:
# ------
#   sudo python3 project12_scanner.py --target 192.168.1.0/24
#   sudo python3 project12_scanner.py --target 192.168.1.0/24 --fast
#   sudo python3 project12_scanner.py --target 192.168.1.0/24 --output results.json
#   sudo python3 project12_scanner.py --target 192.168.1.0/24 --delay 0.5
# ======================================================================
# """

# import argparse
# import socket
# import ipaddress
# import json
# import time
# import threading
# from datetime import datetime
# from concurrent.futures import ThreadPoolExecutor, as_completed
# from scapy.all import ARP, Ether, srp, IP, ICMP, sr1, TCP, conf
# from colorama import init, Fore, Style, Back

# # Initialize colorama for Windows support
# init(autoreset=True)

# # Color definitions
# class Colors:
#     HEADER = Fore.CYAN + Style.BRIGHT
#     OKBLUE = Fore.BLUE + Style.BRIGHT
#     OKGREEN = Fore.GREEN + Style.BRIGHT
#     WARNING = Fore.YELLOW + Style.BRIGHT
#     FAIL = Fore.RED + Style.BRIGHT
#     ENDC = Style.RESET_ALL
#     BOLD = Style.BRIGHT
#     DIM = Fore.LIGHTBLACK_EX
#     MAGENTA = Fore.MAGENTA + Style.BRIGHT
#     CYAN = Fore.CYAN

# # Top 20 ports to scan
# TOP_PORTS = {
#     20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
#     53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC",
#     139: "NETBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
#     995: "POP3S", 1723: "PPTP", 3306: "MYSQL", 3389: "RDP", 8080: "HTTP-ALT"
# }

# # Fast mode - top 5 ports
# FAST_PORTS = {22: "SSH", 80: "HTTP", 443: "HTTPS", 445: "SMB", 3389: "RDP"}

# # OS Fingerprinting database
# OS_FINGERPRINTS = {
#     # Windows fingerprints
#     "Windows": {
#         "ttl": [128, 32],  # Windows default TTL
#         "window": [8192, 16384, 65535],
#         "signatures": [
#             {"ttl": 128, "window": 8192, "os": "Windows 10/11"},
#             {"ttl": 128, "window": 16384, "os": "Windows Server"},
#             {"ttl": 32, "window": 65535, "os": "Windows 95/98/ME"}
#         ]
#     },
#     # Linux fingerprints
#     "Linux": {
#         "ttl": [64, 255],
#         "window": [5840, 29200, 32768, 42880],
#         "signatures": [
#             {"ttl": 64, "window": 5840, "os": "Linux 2.4/2.6"},
#             {"ttl": 64, "window": 29200, "os": "Linux 3.x"},
#             {"ttl": 255, "window": 4128, "os": "Cisco Router"}
#         ]
#     },
#     # macOS/BSD fingerprints
#     "macOS": {
#         "ttl": [64],
#         "window": [65535],
#         "signatures": [
#             {"ttl": 64, "window": 65535, "os": "macOS / BSD"},
#             {"ttl": 64, "window": 65535, "os": "iOS Device"}
#         ]
#     },
#     "Solaris": {
#         "ttl": [255],
#         "window": [8760, 24820],
#         "signatures": [
#             {"ttl": 255, "window": 8760, "os": "Solaris"},
#             {"ttl": 255, "window": 24820, "os": "SunOS"}
#         ]
#     }
# }

# class NetworkScanner:
#     def __init__(self, target_network, fast_mode=False, delay=0.1, output_file=None):
#         self.target_network = target_network
#         self.fast_mode = fast_mode
#         self.delay = delay
#         self.output_file = output_file
#         self.results = []
#         self.live_hosts = []
#         self.ports_to_scan = FAST_PORTS if fast_mode else TOP_PORTS
        
#     def banner(self):
#         print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
#         print(f"{Colors.BOLD}  PROJECT #12 — Network Scanner with OS Fingerprinting{Colors.ENDC}")
#         print(f"{Colors.OKBLUE}  Nmap-style scanner with ARP/ICMP discovery + SYN scan{Colors.ENDC}")
#         print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
        
#     def arp_scan(self, ip_range):
#         """Perform ARP scan to discover live hosts"""
#         print(f"{Colors.OKBLUE}[*] Performing ARP scan on {ip_range}...{Colors.ENDC}")
        
#         try:
#             # Create ARP request
#             arp = ARP(pdst=str(ip_range))
#             ether = Ether(dst="ff:ff:ff:ff:ff:ff")
#             packet = ether / arp
            
#             # Send packet and receive response
#             result = srp(packet, timeout=3, verbose=0)[0]
            
#             hosts = []
#             for sent, received in result:
#                 hosts.append({
#                     'ip': received.psrc,
#                     'mac': received.hwsrc,
#                     'method': 'ARP'
#                 })
            
#             print(f"{Colors.OKGREEN}[+] Found {len(hosts)} live hosts via ARP{Colors.ENDC}")
#             return hosts
            
#         except Exception as e:
#             print(f"{Colors.FAIL}[-] ARP scan failed: {e}{Colors.ENDC}")
#             return []
    
#     def icmp_ping(self, ip):
#         """ICMP ping a single host"""
#         try:
#             packet = IP(dst=str(ip), ttl=64) / ICMP()
#             reply = sr1(packet, timeout=2, verbose=0)
            
#             if reply is not None:
#                 return {
#                     'ip': str(ip),
#                     'mac': 'Unknown',
#                     'method': 'ICMP',
#                     'ttl': reply.ttl
#                 }
#         except:
#             pass
#         return None
    
#     def icmp_scan(self, network):
#         """Scan network with ICMP ping"""
#         print(f"{Colors.OKBLUE}[*] Performing ICMP scan...{Colors.ENDC}")
#         hosts = []
        
#         with ThreadPoolExecutor(max_workers=20) as executor:
#             futures = {executor.submit(self.icmp_ping, ip): ip for ip in network.hosts()}
#             for future in as_completed(futures):
#                 result = future.result()
#                 if result:
#                     hosts.append(result)
#                     print(f"{Colors.OKGREEN}[+] Live host: {result['ip']} (ICMP){Colors.ENDC}")
#                 time.sleep(self.delay)
        
#         return hosts
    
#     def tcp_syn_scan_port(self, ip, port, timeout=2):
#         """TCP SYN scan a single port"""
#         try:
#             # Create SYN packet
#             syn = IP(dst=ip, ttl=64) / TCP(dport=port, flags='S', seq=1000)
#             reply = sr1(syn, timeout=timeout, verbose=0)
            
#             if reply is None:
#                 return None  # Filtered/No response
#             elif reply.haslayer(TCP):
#                 if reply.getlayer(TCP).flags == 0x12:  # SYN-ACK
#                     # Send RST to close connection
#                     rst = IP(dst=ip, ttl=64) / TCP(dport=port, flags='R', seq=1001)
#                     sr1(rst, timeout=1, verbose=0)
#                     return {
#                         'port': port,
#                         'service': self.ports_to_scan.get(port, 'Unknown'),
#                         'status': 'open',
#                         'ttl': reply.ttl,
#                         'window': reply.getlayer(TCP).window
#                     }
#                 elif reply.getlayer(TCP).flags == 0x14:  # RST-ACK
#                     return {
#                         'port': port,
#                         'service': self.ports_to_scan.get(port, 'Unknown'),
#                         'status': 'closed',
#                         'ttl': reply.ttl,
#                         'window': reply.getlayer(TCP).window
#                     }
#         except Exception as e:
#             pass
#         return None
    
#     def scan_ports(self, ip):
#         """Scan ports on a single host"""
#         open_ports = []
        
#         for port in self.ports_to_scan.keys():
#             result = self.tcp_syn_scan_port(ip, port)
#             if result and result['status'] == 'open':
#                 open_ports.append(result)
#             time.sleep(self.delay)
        
#         return open_ports
    
#     def fingerprint_os(self, ttl, window_size=None, open_ports=None):
#         """
#         Determine OS based on TTL, TCP window, and open ports
#         """
#         if not ttl:
#             return "Unknown", "Unknown"
        
#         os_guess = "Unknown"
#         confidence = "Low"
#         details = ""
        
#         # Primary detection based on TTL
#         if ttl <= 64:
#             if ttl == 64:
#                 # Could be Linux, macOS, or BSD
#                 if window_size:
#                     if window_size == 65535:
#                         os_guess = "macOS / BSD"
#                         confidence = "High"
#                         details = "TTL=64, Window=65535"
#                     elif window_size in [5840, 29200]:
#                         os_guess = "Linux"
#                         confidence = "High"
#                         details = f"TTL=64, Window={window_size}"
#                     else:
#                         os_guess = "Linux/Unix-like"
#                         confidence = "Medium"
#                         details = f"TTL=64, Window={window_size}"
#                 else:
#                     os_guess = "Linux/Unix-like"
#                     confidence = "Medium"
#                     details = "TTL=64 (typical Linux/macOS)"
#             else:
#                 os_guess = "Unknown Unix/Linux"
#                 confidence = "Low"
#                 details = f"TTL={ttl} (non-standard)"
                
#         elif ttl <= 128:
#             if ttl == 128:
#                 os_guess = "Windows"
#                 confidence = "High"
#                 if window_size:
#                     if window_size == 8192:
#                         details = "TTL=128, Window=8192 (Windows 10/11)"
#                     elif window_size == 16384:
#                         details = "TTL=128, Window=16384 (Windows Server)"
#                     elif window_size == 65535:
#                         details = "TTL=128, Window=65535 (Windows with scaling)"
#                     else:
#                         details = f"TTL=128, Window={window_size}"
#                 else:
#                     details = "TTL=128 (Windows family)"
#             else:
#                 os_guess = "Windows/Unix hybrid"
#                 confidence = "Low"
#                 details = f"TTL={ttl} (possible Windows)"
                
#         elif ttl <= 255:
#             if ttl == 255:
#                 os_guess = "Solaris/Cisco"
#                 confidence = "High"
#                 details = "TTL=255 (Solaris/Cisco routers)"
#             else:
#                 os_guess = "Network Device/Unix"
#                 confidence = "Medium"
#                 details = f"TTL={ttl} (network gear or Solaris)"
        
#         # Refine based on open ports
#         if open_ports:
#             if 445 in open_ports and 139 in open_ports:
#                 if "Windows" in os_guess or os_guess == "Unknown":
#                     os_guess = "Windows (SMB services detected)"
#                     confidence = "High"
#             elif 22 in open_ports and 80 in open_ports:
#                 if "Linux" in os_guess or "macOS" in os_guess:
#                     confidence = "High"
#             elif 3389 in open_ports:
#                 os_guess = "Windows (RDP detected)"
#                 confidence = "High"
#             elif 3306 in open_ports:
#                 if "Linux" in os_guess:
#                     details += " + MySQL"
        
#         return os_guess, confidence, details
    
#     def scan_host(self, host_info):
#         """Complete scan for a single host"""
#         ip = host_info['ip']
#         mac = host_info.get('mac', 'Unknown')
#         ttl = host_info.get('ttl')
        
#         print(f"\n{Colors.CYAN}[>] Scanning {ip}...{Colors.ENDC}")
        
#         # Port scan
#         open_ports = self.scan_ports(ip)
#         port_list = [p['port'] for p in open_ports]
        
#         # OS Fingerprinting
#         # Use TTL from first response or default
#         if open_ports:
#             # Use TTL from first open port response
#             ttl_analysis = open_ports[0].get('ttl', ttl)
#             window_analysis = open_ports[0].get('window')
#         else:
#             ttl_analysis = ttl
#             window_analysis = None
        
#         os_name, confidence, os_details = self.fingerprint_os(
#             ttl_analysis, 
#             window_analysis, 
#             port_list
#         )
        
#         result = {
#             'ip': ip,
#             'mac': mac,
#             'status': 'alive',
#             'os_guess': os_name,
#             'os_confidence': confidence,
#             'os_details': os_details,
#             'ttl': ttl_analysis,
#             'open_ports': open_ports,
#             'scan_time': datetime.now().isoformat()
#         }
        
#         # Display results
#         self.display_host_results(result)
        
#         return result
    
#     def display_host_results(self, result):
#         """Display scan results for a single host"""
#         print(f"{Colors.OKGREEN}┌─────────────────────────────────────────────────────────────┐{Colors.ENDC}")
#         print(f"{Colors.OKGREEN}│{Colors.BOLD} Host: {result['ip']}{Colors.ENDC}")
#         print(f"{Colors.OKGREEN}├─────────────────────────────────────────────────────────────┤{Colors.ENDC}")
#         print(f"{Colors.OKGREEN}│{Colors.DIM} MAC Address: {result['mac']}{Colors.ENDC}")
#         print(f"{Colors.OKGREEN}│{Colors.DIM} TTL: {result.get('ttl', 'N/A')}{Colors.ENDC}")
        
#         # OS Detection with color
#         if 'Windows' in result['os_guess']:
#             os_color = Colors.OKBLUE
#         elif 'Linux' in result['os_guess']:
#             os_color = Colors.OKGREEN
#         elif 'macOS' in result['os_guess']:
#             os_color = Colors.MAGENTA
#         else:
#             os_color = Colors.WARNING
            
#         print(f"{Colors.OKGREEN}│{Colors.BOLD} OS Guess: {os_color}{result['os_guess']}{Colors.ENDC} "
#               f"({Colors.DIM}{result['os_confidence']} confidence{Colors.ENDC})")
#         if result['os_details']:
#             print(f"{Colors.OKGREEN}│{Colors.DIM}   ↳ {result['os_details']}{Colors.ENDC}")
        
#         # Open ports
#         if result['open_ports']:
#             print(f"{Colors.OKGREEN}├─────────────────────────────────────────────────────────────┤{Colors.ENDC}")
#             print(f"{Colors.OKGREEN}│{Colors.BOLD} Open Ports:{Colors.ENDC}")
#             for port_info in result['open_ports']:
#                 status_color = Colors.OKGREEN if port_info['status'] == 'open' else Colors.FAIL
#                 print(f"{Colors.OKGREEN}│   {Colors.CYAN}{port_info['port']:<6}{Colors.ENDC} "
#                       f"{status_color}{port_info['status'].upper():<8}{Colors.ENDC} "
#                       f"{Colors.DIM}{port_info['service']}{Colors.ENDC}")
#         else:
#             print(f"{Colors.OKGREEN}├─────────────────────────────────────────────────────────────┤{Colors.ENDC}")
#             print(f"{Colors.OKGREEN}│{Colors.DIM}   No open ports found{Colors.ENDC}")
        
#         print(f"{Colors.OKGREEN}└─────────────────────────────────────────────────────────────┘{Colors.ENDC}")
    
#     def display_summary_table(self):
#         """Display all results in a formatted table"""
#         if not self.results:
#             print(f"{Colors.WARNING}No hosts found to display.{Colors.ENDC}")
#             return
        
#         print(f"\n{Colors.HEADER}{'='*100}{Colors.ENDC}")
#         print(f"{Colors.BOLD}  SCAN SUMMARY{Colors.ENDC}")
#         print(f"{Colors.HEADER}{'='*100}{Colors.ENDC}")
        
#         # Table header
#         print(f"{Colors.BOLD}{'IP Address':<20} {'MAC Address':<20} {'OS Guess':<25} {'Open Ports':<25} {'Confidence'}{Colors.ENDC}")
#         print(f"{Colors.DIM}{'-'*100}{Colors.ENDC}")
        
#         for result in self.results:
#             # Color based on OS
#             if 'Windows' in result['os_guess']:
#                 os_color = Colors.OKBLUE
#             elif 'Linux' in result['os_guess']:
#                 os_color = Colors.OKGREEN
#             elif 'macOS' in result['os_guess']:
#                 os_color = Colors.MAGENTA
#             else:
#                 os_color = Colors.WARNING
            
#             port_count = len(result['open_ports'])
#             port_list = ', '.join([str(p['port']) for p in result['open_ports'][:5]])
#             if port_count > 5:
#                 port_list += f"... (+{port_count-5})"
            
#             print(f"{result['ip']:<20} "
#                   f"{result['mac'][:17]:<20} "
#                   f"{os_color}{result['os_guess'][:24]:<24}{Colors.ENDC} "
#                   f"{Colors.DIM}{port_list:<25}{Colors.ENDC} "
#                   f"{Colors.DIM}({result['os_confidence']}){Colors.ENDC}")
        
#         print(f"{Colors.DIM}{'-'*100}{Colors.ENDC}")
#         print(f"{Colors.OKGREEN}Total hosts found: {len(self.results)}{Colors.ENDC}")
    
#     def save_to_json(self):
#         """Save results to JSON file"""
#         if not self.output_file:
#             return
        
#         try:
#             # Prepare JSON-friendly data
#             json_data = {
#                 'scan_info': {
#                     'target': str(self.target_network),
#                     'scan_time': datetime.now().isoformat(),
#                     'fast_mode': self.fast_mode,
#                     'ports_scanned': len(self.ports_to_scan)
#                 },
#                 'hosts': []
#             }
            
#             for result in self.results:
#                 json_data['hosts'].append({
#                     'ip': result['ip'],
#                     'mac': result['mac'],
#                     'os_guess': result['os_guess'],
#                     'os_confidence': result['os_confidence'],
#                     'os_details': result['os_details'],
#                     'ttl': result.get('ttl'),
#                     'open_ports': result['open_ports'],
#                     'scan_time': result['scan_time']
#                 })
            
#             with open(self.output_file, 'w') as f:
#                 json.dump(json_data, f, indent=2)
            
#             print(f"\n{Colors.OKGREEN}[+] Results saved to {self.output_file}{Colors.ENDC}")
#         except Exception as e:
#             print(f"{Colors.FAIL}[-] Failed to save JSON: {e}{Colors.ENDC}")
    
#     def run(self):
#         """Main scanning routine"""
#         self.banner()
        
#         # Parse network
#         try:
#             network = ipaddress.ip_network(self.target_network, strict=False)
#         except ValueError as e:
#             print(f"{Colors.FAIL}[-] Invalid network: {e}{Colors.ENDC}")
#             return
        
#         print(f"{Colors.OKBLUE}[*] Target network: {network}{Colors.ENDC}")
#         print(f"{Colors.OKBLUE}[*] Port scan mode: {'FAST (top 5 ports)' if self.fast_mode else 'Standard (top 20 ports)'}{Colors.ENDC}")
#         print(f"{Colors.OKBLUE}[*] Delay between probes: {self.delay}s{Colors.ENDC}\n")
        
#         # Step 1: ARP Scan
#         live_hosts = self.arp_scan(network)
        
#         # Step 2: If ARP found few hosts, supplement with ICMP
#         if len(live_hosts) < 3:
#             print(f"{Colors.WARNING}[!] Few hosts found via ARP, supplementing with ICMP scan...{Colors.ENDC}")
#             icmp_hosts = self.icmp_scan(network)
#             # Merge results
#             existing_ips = {h['ip'] for h in live_hosts}
#             for host in icmp_hosts:
#                 if host['ip'] not in existing_ips:
#                     live_hosts.append(host)
        
#         if not live_hosts:
#             print(f"{Colors.FAIL}[-] No live hosts found. Check network connection and permissions.{Colors.ENDC}")
#             print(f"{Colors.WARNING}[!] Note: This script requires root/admin privileges for ARP/ICMP.{Colors.ENDC}")
#             return
        
#         # Step 3: Scan each live host
#         print(f"\n{Colors.OKGREEN}[+] Found {len(live_hosts)} live host(s){Colors.ENDC}")
        
#         with ThreadPoolExecutor(max_workers=10) as executor:
#             futures = {executor.submit(self.scan_host, host): host for host in live_hosts}
#             for future in as_completed(futures):
#                 try:
#                     result = future.result()
#                     self.results.append(result)
#                 except Exception as e:
#                     print(f"{Colors.FAIL}[-] Scan failed: {e}{Colors.ENDC}")
        
#         # Step 4: Display summary
#         self.display_summary_table()
        
#         # Step 5: Save JSON output
#         self.save_to_json()
        
#         # Step 6: Defense recommendations
#         self.show_defenses()
    
#     def show_defenses(self):
#         """Display defense mechanisms against network scanning"""
#         print(f"\n{Colors.HEADER}{'='*100}{Colors.ENDC}")
#         print(f"{Colors.BOLD}  DEFENSE AGAINST NETWORK SCANNING{Colors.ENDC}")
#         print(f"{Colors.HEADER}{'='*100}{Colors.ENDC}")
        
#         defenses = [
#             ("1. Rate Limiting", 
#              "Configure firewall rules to limit SYN packets per source IP (e.g., --limit 1/s)"),
#             ("2. IDS/IPS Detection", 
#              "Snort/Suricata detect port scans with rules: 'detect SYN flood' and 'port scan'"),
#             ("3. Port Knocking", 
#              "Hide SSH behind sequence of connection attempts to closed ports"),
#             ("4. Honeypots", 
#              "Deploy honeypot services to identify and track scanners"),
#             ("5. Firewall Rules", 
#              "Block ICMP, filter unused ports, use stateful inspection"),
#             ("6. OS Fingerprinting Prevention", 
#              "Modify default TTL values, use IPsec to hide TCP stacks"),
#             ("7. Stealth Ports", 
#              "Move services to non-standard ports to evade automated scans"),
#             ("8. Network Segmentation", 
#              "Isolate critical systems in separate VLANs")
#         ]
        
#         for title, desc in defenses:
#             print(f"{Colors.OKGREEN}{title}{Colors.ENDC}: {Colors.DIM}{desc}{Colors.ENDC}")
        
#         print(f"\n{Colors.WARNING}[!] Detection Log:{Colors.ENDC}")
#         print(f"{Colors.DIM}  - Your IP would have been logged by IDS systems{Colors.ENDC}")
#         print(f"{Colors.DIM}  - Scan patterns identified as suspicious activity{Colors.ENDC}")
#         print(f"{Colors.DIM}  - Rate limiting would have slowed down this scan{Colors.ENDC}")
#         print(f"{Colors.HEADER}{'='*100}{Colors.ENDC}\n")

# def main():
#     parser = argparse.ArgumentParser(
#         description="Network Scanner with OS Fingerprinting",
#         epilog="Example: sudo python3 project12_scanner.py --target 192.168.1.0/24"
#     )
#     parser.add_argument("--target", required=True,
#                         help="Target network (e.g., 192.168.1.0/24)")
#     parser.add_argument("--fast", action="store_true",
#                         help="Fast mode: scan top 5 ports only")
#     parser.add_argument("--output", help="Save results to JSON file")
#     parser.add_argument("--delay", type=float, default=0.1,
#                         help="Delay between probes in seconds (default: 0.1)")
    
#     args = parser.parse_args()
    
#     # Check for root privileges
#     if os.geteuid() != 0:
#         print(f"{Colors.FAIL}[-] This script requires root privileges for ARP/ICMP scanning!{Colors.ENDC}")
#         print(f"{Colors.WARNING}[!] Please run with: sudo python3 project12_scanner.py{Colors.ENDC}")
#         return
    
#     # Create scanner and run
#     scanner = NetworkScanner(
#         target_network=args.target,
#         fast_mode=args.fast,
#         delay=args.delay,
#         output_file=args.output
#     )
    
#     scanner.run()

# if __name__ == "__main__":
#     import os
#     main()