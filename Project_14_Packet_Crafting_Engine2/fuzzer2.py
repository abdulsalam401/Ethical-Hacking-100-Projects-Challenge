#!/usr/bin/env python3
"""
==============================================================
  PROJECT #14 — Packet Crafting Engine (Custom Protocol Fuzzer)
  100 Ethical Hacking Projects Series
  
  Features:
  - Craft custom TCP/UDP/ICMP packets
  - Fuzzing mode (randomize flags, payload, ports)
  - Response analysis (SYN-ACK, RST, ICMP errors)
  - Anomaly detection and logging
==============================================================

DEFENSE AGAINST PACKET FUZZING:
1. Input Validation - Validate all packet fields before processing
2. Rate Limiting - Limit packets per second from single IP
3. Stateful Firewall - Track connection state, drop invalid packets
4. IDS/IPS Signatures - Detect fuzzing patterns
5. Protocol Validation - Drop packets with invalid flags/fields
6. Sandboxing - Isolate vulnerable services
7. Patch Management - Fix discovered vulnerabilities quickly
8. Network Segmentation - Limit exposure of vulnerable services

USAGE:
--------
  # Basic TCP SYN packet
  sudo python3 project14_fuzzer.py --target 127.0.0.1 --protocol tcp --dport 80 --flags S
  
  # UDP packet with custom payload
  sudo python3 project14_fuzzer.py --target 127.0.0.1 --protocol udp --dport 53 --payload "test"
  
  # ICMP echo request
  sudo python3 project14_fuzzer.py --target 8.8.8.8 --protocol icmp --icmp-type 8
  
  # Fuzzing mode - random flags
  sudo python3 project14_fuzzer.py --target 127.0.0.1 --protocol tcp --dport 80 --fuzz-flags --count 10
  
  # Fuzzing mode - random payload
  sudo python3 project14_fuzzer.py --target 127.0.0.1 --protocol tcp --dport 80 --fuzz-payload --count 20
  
  # Fuzzing mode - random ports
  sudo python3 project14_fuzzer.py --target 127.0.0.1 --protocol udp --fuzz-port --port-range 1-1000 --count 50
  
  # Full fuzzing (all options)
  sudo python3 project14_fuzzer.py --target 127.0.0.1 --protocol tcp --fuzz-flags --fuzz-payload --fuzz-port --count 30
==============================================================
"""

import argparse
import sys
import time
import random
import string
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Colors for output
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

# Try to import scapy
try:
    from scapy.all import IP, TCP, UDP, ICMP, sr1, sr, Ether, RandIP, RandShort
    from scapy.all import conf, get_if_list, Raw
    SCAPY_AVAILABLE = True
except ImportError as e:
    print(f"{Colors.FAIL}[-] Scapy not installed! Run: pip3 install scapy{Colors.ENDC}")
    SCAPY_AVAILABLE = False

# TCP Flags
TCP_FLAGS = {
    'F': 0x01,  # FIN
    'S': 0x02,  # SYN
    'R': 0x04,  # RST
    'P': 0x08,  # PSH
    'A': 0x10,  # ACK
    'U': 0x20,  # URG
    'E': 0x40,  # ECE
    'C': 0x80,  # CWR
}

# ICMP Types
ICMP_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
}

# ICMP Destination Unreachable Codes
ICMP_UNREACH_CODES = {
    0: "Network Unreachable",
    1: "Host Unreachable",
    2: "Protocol Unreachable",
    3: "Port Unreachable",
    4: "Fragmentation Needed",
    5: "Source Route Failed",
    6: "Destination Network Unknown",
    7: "Destination Host Unknown",
}

class PacketFuzzer:
    def __init__(self, target, protocol, src_port=None, dst_port=None, 
                 flags=None, payload=None, icmp_type=None, count=1, 
                 fuzz_flags=False, fuzz_payload=False, fuzz_port=False,
                 port_range=None, delay=0.1, verbose=True):
        
        self.target = target
        self.protocol = protocol.lower()
        self.src_port = src_port or random.randint(1024, 65535)
        self.dst_port = dst_port
        self.flags = flags.upper() if flags else None
        self.payload = payload
        self.icmp_type = icmp_type
        self.count = count
        self.fuzz_flags = fuzz_flags
        self.fuzz_payload = fuzz_payload
        self.fuzz_port = fuzz_port
        self.port_range = port_range
        self.delay = delay
        self.verbose = verbose
        self.results = []
        self.anomalies = []
        
    def banner(self):
        """Display banner"""
        print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.HEADER}  PROJECT #14 — Packet Crafting Engine (Protocol Fuzzer){Colors.ENDC}")
        print(f"{Colors.OKBLUE}  Custom packet crafting with fuzzing capabilities{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
        
        print(f"{Colors.OKGREEN}[+] Target: {self.target}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Protocol: {self.protocol.upper()}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Count: {self.count}{Colors.ENDC}")
        
        if self.fuzz_flags:
            print(f"{Colors.MAGENTA}[*] Fuzzing: Flags{Colors.ENDC}")
        if self.fuzz_payload:
            print(f"{Colors.MAGENTA}[*] Fuzzing: Payload{Colors.ENDC}")
        if self.fuzz_port:
            print(f"{Colors.MAGENTA}[*] Fuzzing: Ports{Colors.ENDC}")
        print()
    
    def random_payload(self, size_range=(1, 100)):
        """Generate random payload"""
        size = random.randint(*size_range)
        return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=size))
    
    def random_flags(self):
        """Generate random TCP flags"""
        flag_list = list(TCP_FLAGS.keys())
        num_flags = random.randint(1, 3)
        return ''.join(random.sample(flag_list, num_flags))
    
    def random_port(self):
        """Generate random port within range"""
        if self.port_range:
            start, end = map(int, self.port_range.split('-'))
            return random.randint(start, end)
        return random.randint(1, 65535)
    
    def craft_tcp_packet(self, src_port, dst_port, flags, payload):
        """Craft TCP packet"""
        ip = IP(dst=self.target)
        
        # Parse flags
        flag_value = 0
        for f in flags:
            if f in TCP_FLAGS:
                flag_value |= TCP_FLAGS[f]
        
        tcp = TCP(sport=src_port, dport=dst_port, flags=flag_value)
        
        # Add payload if present
        if payload:
            tcp.payload = Raw(load=payload.encode() if isinstance(payload, str) else payload)
        
        return ip/tcp
    
    def craft_udp_packet(self, src_port, dst_port, payload):
        """Craft UDP packet"""
        ip = IP(dst=self.target)
        udp = UDP(sport=src_port, dport=dst_port)
        
        if payload:
            udp.payload = Raw(load=payload.encode() if isinstance(payload, str) else payload)
        
        return ip/udp
    
    def craft_icmp_packet(self, icmp_type, payload):
        """Craft ICMP packet"""
        ip = IP(dst=self.target)
        icmp = ICMP(type=icmp_type)
        
        if payload:
            icmp.payload = Raw(load=payload.encode() if isinstance(payload, str) else payload)
        
        return ip/icmp
    
    def analyze_response(self, response, packet, packet_num):
        """Analyze response packet"""
        result = {
            'packet_num': packet_num,
            'sent': self.packet_summary(packet),
            'received': None,
            'response_time': None,
            'anomaly': False,
            'anomaly_type': None
        }
        
        if response:
            result['received'] = self.packet_summary(response)
            result['response_time'] = response.time - packet.sent_time if hasattr(packet, 'sent_time') else None
            
            # Check for anomalies
            # 1. RST packet (unexpected connection reset)
            if response.haslayer(TCP) and response[TCP].flags == 0x04:
                result['anomaly'] = True
                result['anomaly_type'] = "RST Packet (Connection Reset)"
                self.anomalies.append(result)
            
            # 2. ICMP error responses
            elif response.haslayer(ICMP):
                icmp_type = response[ICMP].type
                icmp_code = response[ICMP].code
                
                if icmp_type == 3:  # Destination Unreachable
                    result['anomaly'] = True
                    unreach_msg = ICMP_UNREACH_CODES.get(icmp_code, f"Unknown Code {icmp_code}")
                    result['anomaly_type'] = f"ICMP Destination Unreachable - {unreach_msg}"
                    self.anomalies.append(result)
                
                elif icmp_type == 11:  # Time Exceeded
                    result['anomaly'] = True
                    result['anomaly_type'] = "ICMP Time Exceeded (TTL expired)"
                    self.anomalies.append(result)
            
            # 3. Unexpected open port (no response when expecting one)
            elif self.protocol == 'tcp' and 'S' in self.flags and response.haslayer(TCP):
                if response[TCP].flags == 0x12:  # SYN-ACK
                    result['anomaly'] = False  # This is normal
                elif response[TCP].flags == 0x14:  # RST-ACK
                    result['anomaly'] = True
                    result['anomaly_type'] = "Port Closed (RST-ACK)"
                    self.anomalies.append(result)
        
        else:
            # No response - possible anomaly for certain packet types
            if self.protocol == 'tcp' and 'S' in self.flags:
                result['anomaly'] = True
                result['anomaly_type'] = "No Response - Port Filtered/Dropped"
                self.anomalies.append(result)
        
        return result
    
    def packet_summary(self, packet):
        """Generate packet summary string"""
        summary = []
        
        if packet.haslayer(IP):
            summary.append(f"IP {packet[IP].src} → {packet[IP].dst}")
        
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = self.get_flag_string(tcp.flags)
            summary.append(f"TCP {tcp.sport}→{tcp.dport} Flags={flags}")
        
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            summary.append(f"UDP {udp.sport}→{udp.dport}")
        
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            summary.append(f"ICMP Type={icmp.type} ({ICMP_TYPES.get(icmp.type, 'Unknown')})")
        
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            summary.append(f"Payload={len(payload)} bytes")
            if len(payload) <= 50:
                summary.append(f"Data={payload}")
        
        return " | ".join(summary)
    
    def get_flag_string(self, flag_value):
        """Convert flag value to string"""
        flags = []
        for name, value in TCP_FLAGS.items():
            if flag_value & value:
                flags.append(name)
        return ''.join(flags) if flags else 'None'
    
    def print_result(self, result):
        """Print packet result"""
        print(f"\n{Colors.CYAN}{'─'*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}[{result['packet_num']}] SENT:{Colors.ENDC} {Colors.DIM}{result['sent']}{Colors.ENDC}")
        
        if result['received']:
            response_time = result.get('response_time', 0)
            time_str = f"{response_time*1000:.2f}ms" if response_time else "N/A"
            print(f"{Colors.OKGREEN}[{result['packet_num']}] RECV:{Colors.ENDC} {Colors.DIM}{result['received']}{Colors.ENDC} {Colors.DIM}({time_str}){Colors.ENDC}")
            
            if result['anomaly']:
                print(f"{Colors.FAIL}[!] ANOMALY: {result['anomaly_type']}{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}[{result['packet_num']}] NO RESPONSE{Colors.ENDC}")
            if result.get('anomaly'):
                print(f"{Colors.FAIL}[!] ANOMALY: {result['anomaly_type']}{Colors.ENDC}")
    
    def send_packet(self, packet, packet_num):
        """Send packet and wait for response"""
        try:
            # Send packet and wait for response (timeout 3 seconds)
            response = sr1(packet, timeout=3, verbose=0)
            return response
        except Exception as e:
            if self.verbose:
                print(f"{Colors.FAIL}[-] Error sending packet: {e}{Colors.ENDC}")
            return None
    
    def run(self):
        """Main execution"""
        self.banner()
        
        if not SCAPY_AVAILABLE:
            return
        
        print(f"{Colors.OKBLUE}[*] Starting fuzzing...{Colors.ENDC}\n")
        
        for i in range(1, self.count + 1):
            # Determine parameters for this packet
            current_src_port = self.src_port
            current_dst_port = self.dst_port
            current_flags = self.flags
            current_payload = self.payload
            
            # Apply fuzzing
            if self.fuzz_port:
                if self.dst_port:
                    current_dst_port = self.random_port()
                if self.src_port:
                    current_src_port = self.random_port()
            
            if self.fuzz_flags and self.protocol == 'tcp':
                current_flags = self.random_flags()
            
            if self.fuzz_payload:
                current_payload = self.random_payload()
            
            # Craft packet based on protocol
            if self.protocol == 'tcp':
                if not current_dst_port:
                    print(f"{Colors.FAIL}[-] TCP requires destination port!{Colors.ENDC}")
                    return
                packet = self.craft_tcp_packet(current_src_port, current_dst_port, 
                                               current_flags, current_payload)
            
            elif self.protocol == 'udp':
                if not current_dst_port:
                    print(f"{Colors.FAIL}[-] UDP requires destination port!{Colors.ENDC}")
                    return
                packet = self.craft_udp_packet(current_src_port, current_dst_port, current_payload)
            
            elif self.protocol == 'icmp':
                icmp_type = self.icmp_type or 8  # Default to Echo Request
                packet = self.craft_icmp_packet(icmp_type, current_payload)
            
            else:
                print(f"{Colors.FAIL}[-] Unsupported protocol: {self.protocol}{Colors.ENDC}")
                return
            
            # Send packet and get response
            response = self.send_packet(packet, i)
            
            # Analyze response
            result = self.analyze_response(response, packet, i)
            self.results.append(result)
            
            # Print result
            self.print_result(result)
            
            # Delay between packets
            time.sleep(self.delay)
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print fuzzing summary"""
        print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}  FUZZING SUMMARY{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
        
        sent_count = len(self.results)
        response_count = sum(1 for r in self.results if r['received'])
        anomaly_count = len(self.anomalies)
        
        print(f"{Colors.OKGREEN}Packets sent: {sent_count}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Responses received: {response_count}{Colors.ENDC}")
        print(f"{Colors.WARNING}Anomalies detected: {anomaly_count}{Colors.ENDC}")
        
        if self.anomalies:
            print(f"\n{Colors.FAIL}ANOMALIES:{Colors.ENDC}")
            for i, anomaly in enumerate(self.anomalies[:10], 1):
                print(f"  {i}. Packet #{anomaly['packet_num']}: {anomaly['anomaly_type']}")
                print(f"     Sent: {anomaly['sent'][:80]}")
            
            if len(self.anomalies) > 10:
                print(f"  ... and {len(self.anomalies) - 10} more anomalies")
        
        # Print defense recommendations
        self.print_defenses()
    
    def print_defenses(self):
        """Print defense mechanisms against packet fuzzing"""
        print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}  DEFENSE AGAINST PACKET FUZZING ATTACKS{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
        
        defenses = [
            ("1. Input Validation", "Validate all packet fields, drop malformed packets"),
            ("2. Rate Limiting", "Limit packets per second from single IP addresses"),
            ("3. Stateful Firewall", "Track connection state, drop invalid state transitions"),
            ("4. IDS/IPS Signatures", "Detect fuzzing patterns and block attackers"),
            ("5. Protocol Validation", "Strictly enforce protocol specifications"),
            ("6. Sandboxing", "Isolate vulnerable services in containers/VMs"),
            ("7. Patch Management", "Quickly patch discovered vulnerabilities"),
            ("8. Network Segmentation", "Limit exposure of critical services"),
            ("9. Honeypots", "Deploy decoy services to detect fuzzing attempts"),
            ("10. Logging & Monitoring", "Log anomalies for forensic analysis")
        ]
        
        for title, desc in defenses:
            print(f"{Colors.OKGREEN}{title}{Colors.ENDC}: {Colors.DIM}{desc}{Colors.ENDC}")
        
        print(f"\n{Colors.WARNING}[!] Detection Log:{Colors.ENDC}")
        print(f"{Colors.DIM}  - Your IP would be flagged by IDS for fuzzing patterns{Colors.ENDC}")
        print(f"{Colors.DIM}  - Rate limiting would slow down this scan{Colors.ENDC}")
        print(f"{Colors.DIM}  - Firewall would log anomalous packets{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")

def test_scenarios():
    """Test scenarios for the fuzzer"""
    print(f"{Colors.HEADER}TEST SCENARIOS{Colors.ENDC}")
    print(f"{Colors.DIM}Run these commands to test the fuzzer:{Colors.ENDC}\n")
    
    tests = [
        ("1. TCP SYN to port 80 (expect SYN-ACK)",
         "sudo python3 project14_fuzzer.py --target 127.0.0.1 --protocol tcp --dport 80 --flags S"),
        
        ("2. TCP SYN to closed port (expect RST)",
         "sudo python3 project14_fuzzer.py --target 127.0.0.1 --protocol tcp --dport 9999 --flags S"),
        
        ("3. UDP to closed port (expect ICMP Port Unreachable)",
         "sudo python3 project14_fuzzer.py --target 127.0.0.1 --protocol udp --dport 54321"),
        
        ("4. ICMP Echo Request",
         "sudo python3 project14_fuzzer.py --target 8.8.8.8 --protocol icmp --icmp-type 8"),
        
        ("5. Fuzz TCP flags (10 packets)",
         "sudo python3 project14_fuzzer.py --target 127.0.0.1 --protocol tcp --dport 80 --fuzz-flags --count 10"),
        
        ("6. Fuzz payload (20 packets)",
         "sudo python3 project14_fuzzer.py --target 127.0.0.1 --protocol udp --dport 53 --fuzz-payload --count 20"),
        
        ("7. Fuzz ports (scan 1-1000)",
         "sudo python3 project14_fuzzer.py --target 127.0.0.1 --protocol tcp --fuzz-port --port-range 1-1000 --count 50"),
        
        ("8. Full fuzzing mode",
         "sudo python3 project14_fuzzer.py --target 127.0.0.1 --protocol tcp --fuzz-flags --fuzz-payload --fuzz-port --count 30")
    ]
    
    for title, command in tests:
        print(f"{Colors.OKGREEN}{title}{Colors.ENDC}")
        print(f"{Colors.DIM}  {command}{Colors.ENDC}\n")

def main():
    parser = argparse.ArgumentParser(
        description="Packet Crafting Engine - Custom Protocol Fuzzer",
        epilog="Example: sudo python3 project14_fuzzer.py --target 127.0.0.1 --protocol tcp --dport 80 --flags S"
    )
    
    # Target options
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--protocol", required=True, choices=['tcp', 'udp', 'icmp'], 
                        help="Protocol to use")
    
    # Port options
    parser.add_argument("--sport", type=int, help="Source port")
    parser.add_argument("--dport", type=int, help="Destination port")
    
    # TCP options
    parser.add_argument("--flags", help="TCP flags (S=SYN, A=ACK, R=RST, F=FIN, P=PSH, U=URG)")
    
    # ICMP options
    parser.add_argument("--icmp-type", type=int, choices=[0, 3, 4, 5, 8, 11, 12, 13, 14],
                        help="ICMP type (8=Echo Request, 0=Echo Reply)")
    
    # Payload
    parser.add_argument("--payload", help="Custom payload data")
    
    # Fuzzing options
    parser.add_argument("--fuzz-flags", action="store_true", help="Randomize TCP flags")
    parser.add_argument("--fuzz-payload", action="store_true", help="Randomize payload")
    parser.add_argument("--fuzz-port", action="store_true", help="Randomize ports")
    parser.add_argument("--port-range", help="Port range for fuzzing (e.g., 1-1000)")
    
    # Execution options
    parser.add_argument("--count", type=int, default=1, help="Number of packets to send")
    parser.add_argument("--delay", type=float, default=0.1, help="Delay between packets (seconds)")
    parser.add_argument("--quiet", action="store_true", help="Reduce output verbosity")
    
    # Test scenarios
    parser.add_argument("--test", action="store_true", help="Show test scenarios")
    
    args = parser.parse_args()
    
    if args.test:
        test_scenarios()
        return
    
    # Check for root privileges
    if os.geteuid() != 0:
        print(f"{Colors.FAIL}[-] This script requires root privileges for raw socket access!{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] Please run with: sudo python3 {sys.argv[0]}{Colors.ENDC}")
        return
    
    # Create fuzzer
    fuzzer = PacketFuzzer(
        target=args.target,
        protocol=args.protocol,
        src_port=args.sport,
        dst_port=args.dport,
        flags=args.flags,
        payload=args.payload,
        icmp_type=args.icmp_type,
        count=args.count,
        fuzz_flags=args.fuzz_flags,
        fuzz_payload=args.fuzz_payload,
        fuzz_port=args.fuzz_port,
        port_range=args.port_range,
        delay=args.delay,
        verbose=not args.quiet
    )
    
    try:
        fuzzer.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Fuzzing interrupted by user{Colors.ENDC}")
        fuzzer.print_summary()
    except Exception as e:
        print(f"{Colors.FAIL}[-] Error: {e}{Colors.ENDC}")

if __name__ == "__main__":
    import os
    main()