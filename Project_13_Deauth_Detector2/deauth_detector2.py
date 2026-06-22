#!/usr/bin/env python3
"""
Project #13: WiFi Deauthentication Detector (Fixed Version)
"""

import os
import sys
import time
import signal
from datetime import datetime

# Simple color codes (avoiding scapy color issues)
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    DIM = '\033[2m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

# Try to import scapy
try:
    from scapy.all import sniff, Dot11, Dot11Deauth, RadioTap
    SCAPY_AVAILABLE = True
except ImportError as e:
    print(f"{Colors.RED}[-] Scapy not installed! Run: pip3 install scapy{Colors.RESET}")
    SCAPY_AVAILABLE = False

# Deauth reason codes
REASON_CODES = {
    1: "Unspecified reason",
    2: "Previous authentication no longer valid",
    3: "Deauthenticated because sending station is leaving",
    4: "Disassociated due to inactivity",
    5: "Disassociated because AP is unable to handle",
    6: "Class 2 frame from nonauthenticated station",
    7: "Class 3 frame from nonassociated station",
    8: "Disassociated because sending station is leaving",
    9: "Station requesting (re)association is not authenticated",
}

class DeauthDetector:
    def __init__(self, interface, threshold=5, time_window=10):
        self.interface = interface
        self.threshold = threshold
        self.time_window = time_window
        self.deauth_packets = {}  # source_mac -> list of timestamps
        self.alerted_sources = set()
        self.packet_count = 0
        self.deauth_count = 0
        self.running = True
        
    def signal_handler(self, sig, frame):
        print(f"\n{Colors.YELLOW}[!] Stopping detector...{Colors.RESET}")
        self.running = False
        self.print_statistics()
        sys.exit(0)
    
    def print_statistics(self):
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}  DETECTION STATISTICS{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"Total packets captured: {self.packet_count}")
        print(f"Total deauth packets: {self.deauth_count}")
        print(f"Unique attackers: {len(self.deauth_packets)}")
        
        if self.deauth_packets:
            print(f"\n{Colors.YELLOW}Top attackers:{Colors.RESET}")
            sorted_attackers = sorted(self.deauth_packets.items(), 
                                     key=lambda x: len(x[1]), reverse=True)[:5]
            for mac, timestamps in sorted_attackers:
                print(f"  {Colors.RED}{mac}{Colors.RESET}: {len(timestamps)} packets")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")
    
    def check_attack(self, source_mac, target_mac, reason_code):
        """Check if deauth packets indicate an attack"""
        current_time = time.time()
        
        # Clean old timestamps
        if source_mac in self.deauth_packets:
            self.deauth_packets[source_mac] = [
                t for t in self.deauth_packets[source_mac] 
                if current_time - t <= self.time_window
            ]
        else:
            self.deauth_packets[source_mac] = []
        
        # Add current packet
        self.deauth_packets[source_mac].append(current_time)
        
        # Check threshold
        packet_count = len(self.deauth_packets[source_mac])
        
        if packet_count >= self.threshold and source_mac not in self.alerted_sources:
            self.alerted_sources.add(source_mac)
            
            # Print alert
            alert = f"""
{Colors.RED}{'='*60}{Colors.RESET}
{Colors.RED}⚠️⚠️⚠️  DEAUTH ATTACK DETECTED!  ⚠️⚠️⚠️{Colors.RESET}
{Colors.RED}{'='*60}{Colors.RESET}
{Colors.YELLOW}Attacker MAC : {Colors.BOLD}{source_mac}{Colors.RESET}
{Colors.YELLOW}Target MAC   : {Colors.BOLD}{target_mac}{Colors.RESET}
{Colors.YELLOW}Reason Code  : {Colors.BOLD}{reason_code}{Colors.RESET} - {REASON_CODES.get(reason_code, 'Unknown')}
{Colors.YELLOW}Packets      : {Colors.BOLD}{packet_count}{Colors.RESET} in {self.time_window}s
{Colors.YELLOW}Time         : {Colors.BOLD}{datetime.now().strftime('%H:%M:%S')}{Colors.RESET}
{Colors.RED}{'='*60}{Colors.RESET}
"""
            print(alert)
            
            # Mitigation advice
            print(f"{Colors.CYAN}[!] MITIGATION ADVICE:{Colors.RESET}")
            print(f"  • Enable WPA3 with Protected Management Frames (PMF)")
            print(f"  • Enable 802.11w on your router")
            print(f"  • Use wired connection for critical devices")
            print(f"  • Update router firmware")
            print()
            
            return True
        return False
    
    def packet_handler(self, packet):
        """Process captured packets"""
        if not self.running:
            return
        
        self.packet_count += 1
        
        # Check for deauth packets
        if packet.haslayer(Dot11Deauth):
            self.deauth_count += 1
            
            # Extract information
            dot11 = packet.getlayer(Dot11)
            deauth = packet.getlayer(Dot11Deauth)
            
            source_mac = dot11.addr2 if dot11.addr2 else "Unknown"
            target_mac = dot11.addr1 if dot11.addr1 else "Unknown"
            reason_code = deauth.reason
            
            # Print deauth packet
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"{Colors.DIM}[{timestamp}] Deauth: {source_mac} → {target_mac} (Reason: {reason_code}){Colors.RESET}")
            
            # Check for attack
            self.check_attack(source_mac, target_mac, reason_code)
    
    def run(self):
        """Start the detector"""
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}  WiFi Deauthentication Detector{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Interface: {self.interface}{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Threshold: {self.threshold} deauth packets in {self.time_window}s{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Monitoring... Press Ctrl+C to stop{Colors.RESET}\n")
        
        # Set signal handler
        signal.signal(signal.SIGINT, self.signal_handler)
        
        # Start sniffing
        try:
            sniff(iface=self.interface, prn=self.packet_handler, store=False)
        except PermissionError:
            print(f"{Colors.RED}[-] Permission denied! Run with sudo{Colors.RESET}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.RED}[-] Error: {e}{Colors.RESET}")
            sys.exit(1)

def check_interface(interface):
    """Check if interface exists and is in monitor mode"""
    try:
        result = os.popen(f"iwconfig {interface} 2>/dev/null | grep -i monitor").read()
        if not result:
            print(f"{Colors.YELLOW}[!] Warning: {interface} may not be in monitor mode{Colors.RESET}")
    except:
        pass

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="WiFi Deauthentication Detector")
    parser.add_argument("-i", "--interface", required=True, 
                        help="Monitor interface (e.g., wlan0mon)")
    parser.add_argument("-t", "--threshold", type=int, default=5,
                        help="Deauth packets threshold (default: 5)")
    parser.add_argument("-w", "--time-window", type=int, default=10,
                        help="Time window in seconds (default: 10)")
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print(f"{Colors.RED}[-] This script requires root privileges!{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Please run with: sudo python3 {sys.argv[0]}{Colors.RESET}")
        sys.exit(1)
    
    if not SCAPY_AVAILABLE:
        sys.exit(1)
    
    # Check interface
    check_interface(args.interface)
    
    # Run detector
    detector = DeauthDetector(args.interface, args.threshold, args.time_window)
    detector.run()

if __name__ == "__main__":
    main()