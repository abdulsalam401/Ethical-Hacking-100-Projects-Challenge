#!/usr/bin/env python3
"""
==============================================================
  PROJECT #15 — DNS Spoof Detector (Mode 1)
  100 Ethical Hacking Projects Series
  
  Features:
  - Sniffs DNS responses on the network
  - Compares against trusted DNS server (8.8.8.8)
  - Detects DNS spoofing attacks
  - Alerts on mismatched IP resolutions
==============================================================

DEFENSE AGAINST DNS SPOOFING:
1. DNSSEC (DNS Security Extensions) - Cryptographic signing
2. Use Trusted DNS Servers (8.8.8.8, 1.1.1.1, 9.9.9.9)
3. DNS over HTTPS (DoH) or DNS over TLS (DoT)
4. Monitor for suspicious DNS responses
5. Implement DNS spoofing detection (like this script!)

USAGE:
--------
  # Basic sniffing mode
  sudo python3 dns_detector.py --interface eth0
  
  # With trusted DNS server
  sudo python3 dns_detector.py --interface wlan0 --trusted-dns 8.8.8.8
  
  # Save alerts to file
  sudo python3 dns_detector.py --interface eth0 --log spoof_alerts.log
  
  # Test mode (simulate spoofing)
  sudo python3 dns_detector.py --test
==============================================================
"""

import argparse
import sys
import time
import socket
import threading
from collections import defaultdict
from datetime import datetime
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

# Try to import scapy
try:
    from scapy.all import sniff, IP, UDP, DNS, DNSQR, DNSRR, conf
    from scapy.layers.dns import DNSQR, DNSRR
    SCAPY_AVAILABLE = True
except ImportError:
    print(f"{Colors.FAIL}[-] Scapy not installed! Run: pip3 install scapy{Colors.ENDC}")
    SCAPY_AVAILABLE = False

class DNSSpoofDetector:
    def __init__(self, interface, trusted_dns="8.8.8.8", log_file=None):
        self.interface = interface
        self.trusted_dns = trusted_dns
        self.log_file = log_file
        self.dns_cache = {}  # domain -> {trusted_ip, observed_sources}
        self.packet_count = 0
        self.spoof_count = 0
        self.running = True
        
    def banner(self):
        print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.HEADER}  PROJECT #15 — DNS Spoof Detector{Colors.ENDC}")
        print(f"{Colors.OKBLUE}  Monitoring for DNS spoofing attacks{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
        
        print(f"{Colors.OKGREEN}[+] Interface: {self.interface}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Trusted DNS: {self.trusted_dns}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Log file: {self.log_file or 'None'}{Colors.ENDC}")
        print(f"{Colors.WARNING}[*] Monitoring DNS responses... Ctrl+C to stop{Colors.ENDC}\n")
    
    def log_alert(self, domain, spoofed_ip, expected_ip, source_ip):
        """Log spoofing alert"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert = f"[{timestamp}] ⚠️ SPOOF DETECTED: {domain} → {spoofed_ip} (expected {expected_ip}) from {source_ip}"
        
        # Print with color
        print(f"{Colors.FAIL}{'='*70}{Colors.ENDC}")
        print(f"{Colors.FAIL}⚠️ DNS SPOOFING DETECTED!{Colors.ENDC}")
        print(f"{Colors.FAIL}{'='*70}{Colors.ENDC}")
        print(f"{Colors.WARNING}Domain: {Colors.BOLD}{domain}{Colors.ENDC}")
        print(f"{Colors.WARNING}Spoofed IP: {Colors.FAIL}{spoofed_ip}{Colors.ENDC} (expected {Colors.OKGREEN}{expected_ip}{Colors.ENDC})")
        print(f"{Colors.WARNING}Source DNS: {Colors.MAGENTA}{source_ip}{Colors.ENDC}")
        print(f"{Colors.WARNING}Time: {Colors.DIM}{timestamp}{Colors.ENDC}")
        print(f"{Colors.FAIL}{'='*70}{Colors.ENDC}\n")
        
        # Log to file
        if self.log_file:
            with open(self.log_file, 'a') as f:
                f.write(alert + "\n")
        
        self.spoof_count += 1
    
    def resolve_trusted(self, domain):
        """Resolve domain using trusted DNS server"""
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.trusted_dns]
            resolver.timeout = 2
            resolver.lifetime = 2
            
            answers = resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in answers]
        except ImportError:
            # Fallback to socket
            try:
                ip = socket.gethostbyname(domain)
                return [ip]
            except:
                return None
        except Exception as e:
            return None
    
    def packet_handler(self, packet):
        """Process DNS response packets"""
        if not self.running:
            return
        
        # Check for DNS response layer
        if packet.haslayer(DNS) and packet[DNS].qr == 1:  # qr=1 means response
            self.packet_count += 1
            
            # Get DNS response info
            dns_layer = packet[DNS]
            source_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
            
            # Process each answer
            for i in range(dns_layer.ancount):
                answer = dns_layer.an[i]
                if answer.type == 1:  # A record (IPv4)
                    domain = answer.rrname.decode() if isinstance(answer.rrname, bytes) else answer.rrname
                    domain = domain.rstrip('.')
                    observed_ip = answer.rdata
                    
                    # Only process if we have a valid IP
                    if isinstance(observed_ip, bytes):
                        observed_ip = socket.inet_ntoa(observed_ip)
                    
                    # Check if we've seen this domain before
                    if domain not in self.dns_cache:
                        # First time seeing this domain - verify with trusted DNS
                        trusted_ips = self.resolve_trusted(domain)
                        if trusted_ips:
                            self.dns_cache[domain] = {
                                'trusted': trusted_ips,
                                'observed': {}
                            }
                            self.dns_cache[domain]['observed'][source_ip] = observed_ip
                            
                            print(f"{Colors.OKGREEN}[✓] New domain: {domain} → {observed_ip} (trusted: {trusted_ips[0]}){Colors.ENDC}")
                        else:
                            # Can't verify, just log
                            print(f"{Colors.DIM}[?] Domain: {domain} → {observed_ip} (unverified){Colors.ENDC}")
                    else:
                        # Domain seen before - check for spoofing
                        trusted_ips = self.dns_cache[domain]['trusted']
                        
                        if observed_ip not in trusted_ips:
                            # This is suspicious - different IP than trusted
                            self.log_alert(domain, observed_ip, trusted_ips[0], source_ip)
                            
                            # Update observed sources
                            if source_ip not in self.dns_cache[domain]['observed']:
                                self.dns_cache[domain]['observed'][source_ip] = observed_ip
                        else:
                            # Normal response
                            print(f"{Colors.DIM}[{self.packet_count}] {domain} → {observed_ip} (from {source_ip}){Colors.ENDC}")
    
    def start_sniffing(self):
        """Start capturing DNS packets"""
        try:
            # Filter for DNS responses
            filter_str = "udp port 53"
            
            sniff(iface=self.interface, 
                  filter=filter_str,
                  prn=self.packet_handler, 
                  store=False,
                  stop_filter=lambda x: not self.running)
        except PermissionError:
            print(f"{Colors.FAIL}[-] Permission denied! Run with sudo{Colors.ENDC}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.FAIL}[-] Error: {e}{Colors.ENDC}")
            sys.exit(1)
    
    def print_statistics(self):
        """Print detection statistics"""
        print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}  DETECTION STATISTICS{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Total DNS responses: {self.packet_count}{Colors.ENDC}")
        print(f"{Colors.WARNING}Spoofing alerts: {self.spoof_count}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Unique domains tracked: {len(self.dns_cache)}{Colors.ENDC}")
        
        if self.spoof_count > 0:
            print(f"\n{Colors.FAIL}[!] DNS spoofing detected on your network!{Colors.ENDC}")
            print(f"{Colors.WARNING}Check your router for DNS hijacking{Colors.ENDC}")
        else:
            print(f"\n{Colors.OKGREEN}[✓] No DNS spoofing detected{Colors.ENDC}")
        
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
    
    def run(self):
        """Main execution"""
        self.banner()
        self.start_sniffing()

def simulate_spoof():
    """Simulate DNS spoofing for testing"""
    print(f"{Colors.WARNING}[!] Simulating DNS spoofing attack...{Colors.ENDC}")
    print(f"{Colors.DIM}This will send a fake DNS response to test the detector{Colors.ENDC}\n")
    
    from scapy.all import IP, UDP, DNS, DNSRR, send
    
    target_ip = "127.0.0.1"
    spoofed_ip = "1.2.3.4"
    domain = "example.com"
    
    # Craft spoofed DNS response
    ip = IP(src="192.168.1.100", dst=target_ip)  # Fake DNS server IP
    udp = UDP(sport=53, dport=12345)
    dns = DNS(id=1234, qr=1, aa=1, qd=DNSQR(qname=domain), 
              an=DNSRR(rrname=domain, rdata=spoofed_ip))
    
    packet = ip/udp/dns
    send(packet, verbose=False)
    print(f"{Colors.FAIL}⚠️ Sent spoofed response: {domain} → {spoofed_ip}{Colors.ENDC}")

def main():
    parser = argparse.ArgumentParser(description="DNS Spoof Detector")
    parser.add_argument("-i", "--interface", help="Network interface to sniff")
    parser.add_argument("--trusted-dns", default="8.8.8.8", help="Trusted DNS server")
    parser.add_argument("--log", help="Log file for alerts")
    parser.add_argument("--test", action="store_true", help="Run test mode")
    
    args = parser.parse_args()
    
    if args.test:
        simulate_spoof()
        return
    
    if not args.interface:
        print(f"{Colors.FAIL}[-] Please specify interface with --interface{Colors.ENDC}")
        print(f"{Colors.DIM}Available interfaces:{Colors.ENDC}")
        for iface in conf.ifaces:
            print(f"  {iface}")
        sys.exit(1)
    
    if not SCAPY_AVAILABLE:
        sys.exit(1)
    
    detector = DNSSpoofDetector(args.interface, args.trusted_dns, args.log)
    
    try:
        detector.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Stopping detector...{Colors.ENDC}")
        detector.running = False
        time.sleep(1)
        detector.print_statistics()

if __name__ == "__main__":
    main()