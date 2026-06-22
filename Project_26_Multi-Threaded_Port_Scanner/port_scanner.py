#!/usr/bin/env python3
"""
==============================================================
  PROJECT #26 — Multi-Threaded Port Scanner (Nmap-style)
  TCP SYN scan with multi-threading and service detection
==============================================================

FEATURES:
- TCP SYN scan (stealth) with Scapy
- TCP Connect fallback
- Multi-threading (200+ threads)
- Service version detection (banner grabbing)
- Colored table output
- JSON export

DEFENSES AGAINST PORT SCANNING:
1. Firewall Rules - Block/limit incoming connections
2. IDS/IPS - Detect scanning patterns (SYN floods, port sweeps)
3. Rate Limiting - Slow down scanners
4. Port Knocking - Hide services behind sequence
5. Honeypots - Deceptive services to identify scanners
6. Stealth Ports - Move services to non-standard ports

USAGE:
--------
  # Basic scan (top 1000 ports)
  python port_scanner.py --target 127.0.0.1
  
  # Full scan (all ports)
  python port_scanner.py --target 127.0.0.1 --all-ports
  
  # Custom port range
  python port_scanner.py --target 127.0.0.1 --ports 20-100,443,8080
  
  # With rate limiting
  python port_scanner.py --target 127.0.0.1 --rate-limit 100
  
  # JSON output
  python port_scanner.py --target 127.0.0.1 --output results.json
  
  # Top 100 ports only
  python port_scanner.py --target 127.0.0.1 --top-ports 100
==============================================================
"""

import socket
import sys
import time
import threading
import json
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Colors
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

# Common ports and services
COMMON_PORTS = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC',
    139: 'NETBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS',
    995: 'POP3S', 1723: 'PPTP', 3306: 'MYSQL', 3389: 'RDP', 5432: 'POSTGRESQL',
    5900: 'VNC', 6379: 'REDIS', 8080: 'HTTP-ALT', 8443: 'HTTPS-ALT', 27017: 'MONGODB'
}

# Try to import Scapy for SYN scan
try:
    from scapy.all import IP, TCP, sr1, conf
    from scapy.all import RandShort
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print(f"{Colors.WARNING}[!] Scapy not installed. Using TCP Connect only.{Colors.ENDC}")

class PortScanner:
    def __init__(self, target, ports=None, top_ports=1000, rate_limit=0, timeout=2, verbose=False):
        self.target = target
        self.ports = ports or []
        self.top_ports = top_ports
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.verbose = verbose
        self.open_ports = []
        self.lock = threading.Lock()
        self.total_ports = 0
        self.scanned_ports = 0
        
        # Resolve target
        try:
            self.target_ip = socket.gethostbyname(target)
        except:
            self.target_ip = target
        
        print(f"{Colors.OKGREEN}[+] Target: {self.target} ({self.target_ip}){Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Top ports: {self.top_ports}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Rate limit: {self.rate_limit} req/s{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Timeout: {self.timeout}s{Colors.ENDC}")
        
        # Generate port list
        if not self.ports:
            self.generate_port_list()
        else:
            self.ports = self.parse_port_list(ports)
        
        self.total_ports = len(self.ports)
        print(f"{Colors.OKGREEN}[+] Total ports to scan: {self.total_ports}{Colors.ENDC}")
    
    def generate_port_list(self):
        """Generate list of ports to scan"""
        if self.top_ports == 0:
            # Scan all ports 1-65535
            self.ports = list(range(1, 65536))
            return
        
        # Top ports from Nmap
        nmap_top_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
            993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
            20, 26, 43, 57, 67, 68, 69, 70, 79, 81, 88, 102, 106, 109, 
            113, 119, 123, 137, 138, 161, 162, 177, 179, 199, 201, 204, 
            206, 209, 210, 213, 220, 256, 259, 264, 280, 301, 306, 311, 
            340, 350, 351, 352, 354, 356, 358, 366, 369, 370, 371, 373, 
            374, 375, 376, 377, 378, 379, 380, 381, 382, 383, 384, 385, 
            386, 387, 388, 389, 390, 391, 392, 393, 394, 395, 396, 397, 
            398, 399, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 
            410, 411, 412, 413, 414, 415, 416, 417, 418, 419, 420, 421, 
            422, 423, 424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 
            434, 435, 436, 437, 438, 439, 440, 441, 442, 443, 444, 445, 
            446, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 
            458, 459, 460, 461, 462, 463, 464, 465, 466, 467, 468, 469, 
            470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481, 
            482, 483, 484, 485, 486, 487, 488, 489, 490, 491, 492, 493, 
            494, 495, 496, 497, 498, 499, 500
        ]
        
        # Take top N ports
        self.ports = nmap_top_ports[:self.top_ports]
        
        # If top_ports > len(nmap_top_ports), add more
        if self.top_ports > len(nmap_top_ports):
            additional = list(range(501, self.top_ports + 1))
            self.ports.extend(additional)
    
    def parse_port_list(self, port_str):
        """Parse port string like '20-100,443,8080'"""
        ports = []
        for part in port_str.split(','):
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return ports
    
    def tcp_syn_scan(self, port):
        """TCP SYN scan using Scapy (stealth)"""
        if not SCAPY_AVAILABLE:
            return None
        
        try:
            # Create SYN packet
            ip = IP(dst=self.target_ip)
            tcp = TCP(sport=RandShort(), dport=port, flags='S')
            packet = ip/tcp
            
            # Send packet and wait for response
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                return None
            
            # Check response flags
            if response.haslayer(TCP):
                if response[TCP].flags == 0x12:  # SYN-ACK
                    # Send RST to close connection (stealth)
                    rst = IP(dst=self.target_ip)/TCP(sport=response[TCP].dport, dport=port, flags='R')
                    sr1(rst, timeout=1, verbose=0)
                    return 'open'
                elif response[TCP].flags == 0x14:  # RST-ACK
                    return 'closed'
            
            return None
            
        except Exception as e:
            if self.verbose:
                print(f"{Colors.DIM}[!] SYN scan error on port {port}: {e}{Colors.ENDC}")
            return None
    
    def tcp_connect_scan(self, port):
        """TCP Connect scan (fallback)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            
            if result == 0:
                return 'open'
            elif result == 111 or result == 61:
                return 'refused'
            else:
                return 'filtered'
                
        except Exception as e:
            if self.verbose:
                print(f"{Colors.DIM}[!] Connect error on port {port}: {e}{Colors.ENDC}")
            return None
    
    def grab_banner(self, port):
        """Grab service banner from open port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP', 80: 'HTTP',
            110: 'POP3', 111: 'RPC', 139: 'NETBIOS', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 3306: 'MYSQL', 3389: 'RDP',
            5432: 'POSTGRESQL', 5900: 'VNC', 6379: 'REDIS', 8080: 'HTTP-ALT',
            8443: 'HTTPS-ALT', 27017: 'MONGODB'
        }
        
        service_name = services.get(port, 'unknown')
        
        try:
            # Try to grab banner
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.target_ip, port))
            
            # Send generic probe
            probes = {
                21: b'QUIT\r\n',
                22: b'SSH-2.0-Client\r\n',
                25: b'HELO test.com\r\n',
                80: b'HEAD / HTTP/1.0\r\n\r\n',
                443: b'HEAD / HTTP/1.0\r\n\r\n',
                3306: b'\x00',
                6379: b'PING\r\n',
                8080: b'HEAD / HTTP/1.0\r\n\r\n'
            }
            
            probe = probes.get(port, b'\n')
            sock.send(probe)
            
            # Receive banner
            banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner:
                # Clean up banner
                banner = ' '.join(banner.split())[:100]
                return f"{service_name} ({banner})"
            
        except:
            pass
        
        return service_name
    
    def scan_port(self, port):
        """Scan a single port"""
        # Rate limiting
        if self.rate_limit > 0:
            time.sleep(1.0 / self.rate_limit)
        
        # Try SYN scan first
        status = self.tcp_syn_scan(port)
        
        # Fallback to TCP Connect if SYN fails
        if status is None and SCAPY_AVAILABLE:
            status = self.tcp_connect_scan(port)
        elif status is None:
            status = self.tcp_connect_scan(port)
        
        with self.lock:
            self.scanned_ports += 1
            
            # Progress indicator
            if self.scanned_ports % 100 == 0 or self.scanned_ports == self.total_ports:
                progress = (self.scanned_ports / self.total_ports) * 100
                print(f"{Colors.DIM}[*] Progress: {self.scanned_ports}/{self.total_ports} ({progress:.1f}%){Colors.ENDC}")
        
        if status == 'open':
            # Grab banner
            service = self.grab_banner(port)
            
            with self.lock:
                self.open_ports.append({
                    'port': port,
                    'status': status,
                    'service': service
                })
                
                # Print immediately
                color = Colors.OKGREEN
                print(f"{color}[+] Port {port}: OPEN - {service}{Colors.ENDC}")
            
            return True
        
        return False
    
    def scan(self):
        """Start the scan"""
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}  PROJECT #26 — Multi-Threaded Port Scanner{Colors.ENDC}")
        print(f"{Colors.OKBLUE}  Nmap-style scanning with SYN and Connect{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        start_time = time.time()
        
        # Use ThreadPoolExecutor for multi-threading
        max_workers = min(200, len(self.ports))
        print(f"{Colors.OKBLUE}[*] Starting scan with {max_workers} threads...{Colors.ENDC}\n")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            futures = {executor.submit(self.scan_port, port): port for port in self.ports}
            
            # Wait for completion
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    if self.verbose:
                        print(f"{Colors.FAIL}[!] Error: {e}{Colors.ENDC}")
        
        elapsed = time.time() - start_time
        
        # Display results
        self.display_results(elapsed)
        
        return self.open_ports
    
    def display_results(self, elapsed):
        """Display scan results in colored table"""
        print(f"\n{Colors.HEADER}{'='*100}{Colors.ENDC}")
        print(f"{Colors.BOLD}  SCAN RESULTS{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*100}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Target: {self.target} ({self.target_ip}){Colors.ENDC}")
        print(f"{Colors.OKGREEN}Ports scanned: {self.total_ports}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Open ports: {len(self.open_ports)}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Time elapsed: {elapsed:.2f}s{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*100}{Colors.ENDC}")
        
        if self.open_ports:
            print(f"\n{Colors.BOLD}{'PORT':<10} {'STATUS':<12} {'SERVICE':<40}{Colors.ENDC}")
            print(f"{Colors.DIM}{'-'*100}{Colors.ENDC}")
            
            for result in sorted(self.open_ports, key=lambda x: x['port']):
                port = result['port']
                status = result['status']
                service = result['service']
                
                # Color based on status
                if status == 'open':
                    status_color = Colors.OKGREEN
                elif status == 'filtered':
                    status_color = Colors.WARNING
                else:
                    status_color = Colors.DIM
                
                print(f"{status_color}{port:<10} {status:<12} {service:<40}{Colors.ENDC}")
        else:
            print(f"\n{Colors.WARNING}[!] No open ports found{Colors.ENDC}")
        
        print(f"{Colors.HEADER}{'='*100}{Colors.ENDC}\n")
    
    def export_json(self, output_file, elapsed):
        """Export results to JSON"""
        if not output_file:
            return
        
        data = {
            'scan_info': {
                'target': self.target,
                'target_ip': self.target_ip,
                'timestamp': datetime.now().isoformat(),
                'ports_scanned': self.total_ports,
                'open_ports_found': len(self.open_ports),
                'time_elapsed': round(elapsed, 2),
                'top_ports': self.top_ports
            },
            'open_ports': self.open_ports
        }
        
        try:
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"{Colors.OKGREEN}[+] Results exported to {output_file}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] Failed to export: {e}{Colors.ENDC}")
    
    def print_defenses(self):
        """Print defense mechanisms against port scanning"""
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}  DEFENSE AGAINST PORT SCANNING{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        
        defenses = [
            ("Firewall Rules", "Block/limit incoming connections, filter suspicious traffic"),
            ("IDS/IPS", "Detect scanning patterns (SYN floods, port sweeps)"),
            ("Rate Limiting", "Slow down scanners with connection limits"),
            ("Port Knocking", "Hide services behind sequence of connection attempts"),
            ("Honeypots", "Deceptive services to identify scanners"),
            ("Stealth Ports", "Move services to non-standard ports"),
            ("Stealth Scanning Detection", "Monitor for unusual SYN packets"),
            ("IP Blocking", "Automatically block scanning IPs")
        ]
        
        for title, desc in defenses:
            print(f"{Colors.OKGREEN}{title}{Colors.ENDC}: {Colors.DIM}{desc}{Colors.ENDC}")
        
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")

def main():
    parser = argparse.ArgumentParser(description="Multi-Threaded Port Scanner")
    parser.add_argument("--target", required=True, help="Target host (IP or domain)")
    parser.add_argument("--ports", help="Port range (e.g., 20-100,443,8080)")
    parser.add_argument("--top-ports", type=int, default=1000, help="Number of top ports to scan (default: 1000)")
    parser.add_argument("--all-ports", action="store_true", help="Scan all ports (1-65535)")
    parser.add_argument("--rate-limit", type=int, default=0, help="Max requests per second")
    parser.add_argument("--timeout", type=float, default=2, help="Timeout per port (default: 2s)")
    parser.add_argument("--output", help="Export results to JSON")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--defenses", action="store_true", help="Show defense mechanisms")
    
    args = parser.parse_args()
    
    # Handle all ports
    if args.all_ports:
        args.top_ports = 0
    
    # Create scanner
    scanner = PortScanner(
        target=args.target,
        ports=args.ports,
        top_ports=args.top_ports,
        rate_limit=args.rate_limit,
        timeout=args.timeout,
        verbose=args.verbose
    )
    
    # Start scan
    try:
        results = scanner.scan()
        scanner.export_json(args.output, 0)
        if args.defenses:
            scanner.print_defenses()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scan interrupted{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}[-] Error: {e}{Colors.ENDC}")

if __name__ == "__main__":
    main()