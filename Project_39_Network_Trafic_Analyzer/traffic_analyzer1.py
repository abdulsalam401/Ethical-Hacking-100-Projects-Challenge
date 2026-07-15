#!/usr/bin/env python3
"""
==============================================================
  PROJECT #39 — Network Traffic Analyzer (Real-time Packet Analysis)
  Live packet capture and analysis with dashboard
==============================================================

⚠️⚠️⚠️  ETHICAL WARNING  ⚠️⚠️⚠️
This tool is for EDUCATIONAL PURPOSES ONLY.
- Only capture traffic on networks you own or have permission to monitor
- Do not use for malicious purposes
- Respect privacy laws
- This is a cybersecurity learning tool

FEATURES:
- Real-time packet capture
- Protocol distribution (HTTP, HTTPS, DNS, SSH, etc.)
- Top talkers (source/destination IPs)
- Connection tracking (TCP/UDP sessions)
- Anomaly detection (SYN flood, port scans, DNS tunneling)
- Live dashboard with curses
- HTML/JSON report generation

DEFENSES AGAINST NETWORK TRAFFIC ANALYSIS:
1. Encryption (TLS/SSL, VPN)
2. Traffic Obfuscation (randomized packet sizes, timing)
3. Protocol Tunneling (DNS over HTTPS, SSH over HTTPS)
4. Network Segmentation
5. VPN/Tor for anonymity
6. Traffic Padding
==============================================================

USAGE:
--------
  # Basic capture on default interface
  sudo python3 traffic_analyzer.py
  
  # Capture on specific interface
  sudo python3 traffic_analyzer.py --interface eth0
  
  # Capture for specific duration
  sudo python3 traffic_analyzer.py --duration 60
  
  # Save report
  sudo python3 traffic_analyzer.py --output report.html
==============================================================
"""

import os
import sys
import time
import threading
import socket
from datetime import datetime
from collections import defaultdict, Counter
import json

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether, ARP, DNS, DNSQR
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.dns import DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[-] Scapy not installed. Run: pip install scapy")

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; MAGENTA=''; WHITE=''
        LIGHTBLACK_EX=''; LIGHTRED_EX=''; LIGHTGREEN_EX=''; LIGHTYELLOW_EX=''
        LIGHTBLUE_EX=''; LIGHTMAGENTA_EX=''; LIGHTCYAN_EX=''
    class Style:
        BRIGHT=''; DIM=''; RESET_ALL=''

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
    RED = Fore.RED + Style.BRIGHT
    YELLOW = Fore.YELLOW + Style.BRIGHT
    GREEN = Fore.GREEN + Style.BRIGHT
    BLUE = Fore.BLUE + Style.BRIGHT
    CYAN = Fore.CYAN + Style.BRIGHT

class TrafficAnalyzer:
    def __init__(self, interface=None, duration=0, output_file="traffic_report.html"):
        self.interface = interface or self.get_default_interface()
        self.duration = duration
        self.output_file = output_file
        self.running = True
        self.packet_count = 0
        self.start_time = None
        self.protocols = defaultdict(int)
        self.top_talkers = defaultdict(int)
        self.top_destinations = defaultdict(int)
        self.connections = defaultdict(int)
        self.syn_packets = []
        self.port_scan_attempts = defaultdict(set)
        self.dns_queries = defaultdict(int)
        self.anomalies = []
        self.lock = threading.Lock()
        self.packet_buffer = []
        
    def get_default_interface(self):
        """Get default network interface"""
        try:
            import netifaces
            return netifaces.gateways()['default'][netifaces.AF_INET][1]
        except:
            return 'eth0'
    
    def banner(self):
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}  PROJECT #39 — Network Traffic Analyzer{Colors.ENDC}")
        print(f"{Colors.OKBLUE}  Real-time packet analysis and anomaly detection{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        print(f"{Colors.RED}⚠️⚠️⚠️  ETHICAL WARNING  ⚠️⚠️⚠️{Colors.ENDC}")
        print(f"{Colors.YELLOW}Only capture traffic on networks you own or have permission to monitor.{Colors.ENDC}\n")
        
        print(f"{Colors.OKGREEN}[+] Interface: {self.interface}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Duration: {self.duration if self.duration > 0 else 'Unlimited'}{Colors.ENDC}\n")
    
    def get_protocol(self, packet):
        """Get protocol of packet"""
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.dport == 80 or tcp.sport == 80:
                return 'HTTP'
            elif tcp.dport == 443 or tcp.sport == 443:
                return 'HTTPS'
            elif tcp.dport == 22 or tcp.sport == 22:
                return 'SSH'
            elif tcp.dport == 53 or tcp.sport == 53:
                return 'DNS'
            elif tcp.dport == 25 or tcp.sport == 25:
                return 'SMTP'
            elif tcp.dport == 21 or tcp.sport == 21:
                return 'FTP'
            else:
                return 'TCP'
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            if udp.dport == 53 or udp.sport == 53:
                return 'DNS'
            elif udp.dport == 67 or udp.sport == 67:
                return 'DHCP'
            elif udp.dport == 123 or udp.sport == 123:
                return 'NTP'
            else:
                return 'UDP'
        elif packet.haslayer(ICMP):
            return 'ICMP'
        elif packet.haslayer(ARP):
            return 'ARP'
        else:
            return 'Other'
    
    def packet_handler(self, packet):
        """Handle captured packet"""
        if not self.running:
            return
        
        with self.lock:
            self.packet_count += 1
            self.packet_buffer.append(packet)
            
            # Process packet
            self.process_packet(packet)
            
            # Check anomalies
            self.check_anomalies(packet)
    
    def process_packet(self, packet):
        """Process packet for statistics"""
        # Protocol
        proto = self.get_protocol(packet)
        self.protocols[proto] += 1
        
        # IP addresses
        if packet.haslayer(IP):
            ip = packet[IP]
            src = ip.src
            dst = ip.dst
            self.top_talkers[src] += 1
            self.top_destinations[dst] += 1
            
            # Connection tracking
            if packet.haslayer(TCP) or packet.haslayer(UDP):
                key = f"{src}:{ip.sport}->{dst}:{ip.dport}"
                self.connections[key] += 1
            
            # SYN flood detection
            if packet.haslayer(TCP) and packet[TCP].flags & 0x02:  # SYN flag
                self.syn_packets.append(time.time())
        
        # DNS queries
        if packet.haslayer(DNS) and packet[DNS].qr == 0:  # Query
            if packet[DNS].qd:
                qname = packet[DNS].qd.qname.decode() if packet[DNS].qd.qname else 'unknown'
                self.dns_queries[qname] += 1
        
        # Port scan detection
        if packet.haslayer(TCP) and packet[TCP].flags & 0x02:  # SYN to different ports
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                self.port_scan_attempts[src_ip].add(packet[TCP].dport)
    
    def check_anomalies(self, packet):
        """Check for anomalies in packet"""
        # SYN flood
        current_time = time.time()
        with self.lock:
            self.syn_packets = [t for t in self.syn_packets if current_time - t <= 1]
            if len(self.syn_packets) > 100:
                if packet.haslayer(IP):
                    anomaly = {
                        'type': 'SYN_FLOOD',
                        'source': packet[IP].src,
                        'details': f'{len(self.syn_packets)} SYN packets in last second',
                        'time': datetime.now().isoformat()
                    }
                    if anomaly not in self.anomalies:
                        self.anomalies.append(anomaly)
                        print(f"{Colors.FAIL}[!] ANOMALY: SYN Flood detected from {packet[IP].src}{Colors.ENDC}")
        
        # Port scan
        with self.lock:
            for src_ip, ports in self.port_scan_attempts.items():
                if len(ports) > 20:
                    anomaly = {
                        'type': 'PORT_SCAN',
                        'source': src_ip,
                        'details': f'{len(ports)} ports scanned',
                        'time': datetime.now().isoformat()
                    }
                    if anomaly not in self.anomalies:
                        self.anomalies.append(anomaly)
                        print(f"{Colors.FAIL}[!] ANOMALY: Port scan detected from {src_ip}{Colors.ENDC}")
                    break
        
        # DNS tunneling (large number of DNS queries)
        with self.lock:
            if len(self.dns_queries) > 50:
                anomaly = {
                    'type': 'DNS_TUNNELING',
                    'source': 'Network',
                    'details': f'{len(self.dns_queries)} unique DNS queries detected',
                    'time': datetime.now().isoformat()
                }
                if anomaly not in self.anomalies:
                    self.anomalies.append(anomaly)
                    print(f"{Colors.FAIL}[!] ANOMALY: Possible DNS tunneling detected{Colors.ENDC}")
    
    def print_live_stats(self):
        """Print live statistics to terminal"""
        os.system('clear' if os.name != 'nt' else 'cls')
        
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}  LIVE TRAFFIC ANALYSIS{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        
        # Stats
        elapsed = time.time() - self.start_time if self.start_time else 0
        print(f"{Colors.OKGREEN}Packets: {self.packet_count} | Elapsed: {elapsed:.1f}s | Rate: {self.packet_count/elapsed:.1f} pps{Colors.ENDC}\n")
        
        # Protocol distribution
        print(f"{Colors.BOLD}Protocol Distribution:{Colors.ENDC}")
        total = sum(self.protocols.values())
        for proto, count in sorted(self.protocols.items(), key=lambda x: x[1], reverse=True)[:8]:
            pct = (count / total * 100) if total > 0 else 0
            bar = '█' * int(pct / 2)
            print(f"  {Colors.CYAN}{proto:<10}{Colors.ENDC} {Colors.OKGREEN}{count:<8}{Colors.ENDC} {Colors.DIM}{pct:>5.1f}% {bar}{Colors.ENDC}")
        
        # Top talkers
        print(f"\n{Colors.BOLD}Top Talkers:{Colors.ENDC}")
        for ip, count in sorted(self.top_talkers.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {Colors.MAGENTA}{ip:<20}{Colors.ENDC} {Colors.OKGREEN}{count}{Colors.ENDC}")
        
        # Top destinations
        print(f"\n{Colors.BOLD}Top Destinations:{Colors.ENDC}")
        for ip, count in sorted(self.top_destinations.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {Colors.MAGENTA}{ip:<20}{Colors.ENDC} {Colors.OKGREEN}{count}{Colors.ENDC}")
        
        # Anomalies
        if self.anomalies:
            print(f"\n{Colors.FAIL}⚠️ Anomalies Detected: {len(self.anomalies)}{Colors.ENDC}")
            for anom in self.anomalies[-5:]:
                print(f"  {Colors.FAIL}• {anom['type']}: {anom['details']}{Colors.ENDC}")
        
        print(f"\n{Colors.DIM}Press Ctrl+C to stop capture{Colors.ENDC}")
    
    def live_dashboard(self):
        """Run live dashboard in separate thread"""
        self.start_time = time.time()
        while self.running:
            self.print_live_stats()
            time.sleep(2)
    
    def start_capture(self):
        """Start packet capture"""
        print(f"{Colors.OKBLUE}[*] Starting packet capture on {self.interface}...{Colors.ENDC}")
        print(f"{Colors.DIM}[*] Press Ctrl+C to stop{Colors.ENDC}\n")
        
        # Start live dashboard in separate thread
        dashboard_thread = threading.Thread(target=self.live_dashboard)
        dashboard_thread.daemon = True
        dashboard_thread.start()
        
        try:
            sniff(iface=self.interface, prn=self.packet_handler, store=False, timeout=self.duration if self.duration > 0 else None)
        except KeyboardInterrupt:
            self.running = False
            print(f"\n{Colors.WARNING}[!] Capture stopped by user{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] Capture error: {e}{Colors.ENDC}")
        finally:
            self.running = False
            dashboard_thread.join(timeout=3)
    
    def generate_report(self):
        """Generate HTML report"""
        print(f"\n{Colors.OKBLUE}[*] Generating report...{Colors.ENDC}")
        
        elapsed = time.time() - self.start_time if self.start_time else 0
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Traffic Analysis Report</title>
    <style>
        body {{font-family:'Segoe UI',sans-serif;background:#1a1a2e;color:#e0e0e0;padding:20px;}}
        .container {{max-width:1200px;margin:0 auto;}}
        .header {{background:linear-gradient(135deg,#16213e,#0f3460);padding:30px;border-radius:10px;}}
        .header h1 {{color:#00d4ff;}}
        .header .warning {{color:#ff4444;font-weight:bold;}}
        .section {{background:#2d2d44;padding:20px;border-radius:10px;margin:15px 0;}}
        .section h2 {{color:#00d4ff;border-bottom:1px solid #3d3d5a;padding-bottom:10px;}}
        .stat-box {{display:inline-block;background:#1a1a3e;padding:15px;border-radius:8px;margin:5px;min-width:150px;text-align:center;}}
        .stat-box .value {{font-size:24px;font-weight:bold;color:#00d4ff;}}
        .stat-box .label {{color:#888;font-size:12px;}}
        .anomaly {{background:#2d2d44;padding:15px;margin:10px 0;border-radius:8px;border-left:4px solid #ff0040;}}
        .anomaly .type {{color:#ff0040;font-weight:bold;}}
        table {{width:100%;border-collapse:collapse;margin:10px 0;}}
        th, td {{padding:10px;text-align:left;border-bottom:1px solid #3d3d5a;}}
        th {{color:#00d4ff;}}
        .defense {{background:#0f3460;padding:15px;border-radius:8px;margin-top:20px;}}
        .defense h3 {{color:#00d4ff;}}
        .defense td {{color:#ccc;padding:5px;}}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>📡 Traffic Analysis Report</h1>
        <p class="warning">⚠️ EDUCATIONAL USE ONLY ⚠️</p>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Interface: {self.interface}</p>
        <p>Capture Duration: {elapsed:.1f}s</p>
    </div>
    
    <div class="section">
        <h2>📊 Summary</h2>
        <div>
            <div class="stat-box"><div class="value">{self.packet_count}</div><div class="label">Total Packets</div></div>
            <div class="stat-box"><div class="value">{len(self.protocols)}</div><div class="label">Protocols</div></div>
            <div class="stat-box"><div class="value">{len(self.top_talkers)}</div><div class="label">Unique IPs</div></div>
            <div class="stat-box"><div class="value">{len(self.anomalies)}</div><div class="label">Anomalies</div></div>
        </div>
    </div>
    
    <div class="section">
        <h2>📊 Protocol Distribution</h2>
        <table>
            <tr><th>Protocol</th><th>Packets</th><th>Percentage</th></tr>"""
        
        total = sum(self.protocols.values())
        for proto, count in sorted(self.protocols.items(), key=lambda x: x[1], reverse=True):
            pct = (count / total * 100) if total > 0 else 0
            html += f"""
            <tr>
                <td>{proto}</td>
                <td>{count}</td>
                <td>{pct:.1f}%</td>
            </tr>"""
        
        html += """
        </table>
    </div>
    
    <div class="section">
        <h2>📋 Top Talkers</h2>
        <table>
            <tr><th>IP Address</th><th>Packets</th></tr>"""
        
        for ip, count in sorted(self.top_talkers.items(), key=lambda x: x[1], reverse=True)[:20]:
            html += f"""
            <tr>
                <td>{ip}</td>
                <td>{count}</td>
            </tr>"""
        
        html += """
        </table>
    </div>
    
    <div class="section">
        <h2>🎯 Top Destinations</h2>
        <table>
            <tr><th>IP Address</th><th>Packets</th></tr>"""
        
        for ip, count in sorted(self.top_destinations.items(), key=lambda x: x[1], reverse=True)[:20]:
            html += f"""
            <tr>
                <td>{ip}</td>
                <td>{count}</td>
            </tr>"""
        
        html += """
        </table>
    </div>
    
    <div class="section">
        <h2>⚠️ Anomalies Detected</h2>"""
        
        if self.anomalies:
            for anom in self.anomalies:
                html += f"""
        <div class="anomaly">
            <div class="type">[{anom['type']}]</div>
            <div><strong>Source:</strong> {anom.get('source', 'Unknown')}</div>
            <div><strong>Details:</strong> {anom['details']}</div>
            <div><strong>Time:</strong> {anom['time']}</div>
        </div>"""
        else:
            html += '<p style="color:#00ff88;">✅ No anomalies detected</p>'
        
        html += """
    </div>
    
    <div class="section defense">
        <h3>🛡️ Defenses Against Network Traffic Analysis</h3>
        <table>
            <tr><th>Defense</th><th>Description</th></tr>
            <tr><td>Encryption</td><td>Use TLS/SSL, VPN for encrypted traffic</td></tr>
            <tr><td>Traffic Obfuscation</td><td>Randomize packet sizes and timing</td></tr>
            <tr><td>Protocol Tunneling</td><td>Hide traffic in other protocols</td></tr>
            <tr><td>Network Segmentation</td><td>Separate network segments</td></tr>
            <tr><td>VPN/Tor</td><td>Anonymize traffic</td></tr>
            <tr><td>Traffic Padding</td><td>Add dummy packets to obscure patterns</td></tr>
        </table>
    </div>
    
    <div style="text-align:center;color:#666;margin-top:30px;">
        <p>Generated by Traffic Analyzer | 100 Ethical Hacking Projects</p>
        <p>⚠️ For Educational Purposes Only ⚠️</p>
    </div>
</div>
</body>
</html>"""
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"{Colors.OKGREEN}[+] Report saved to {self.output_file}{Colors.ENDC}")
    
    def run(self):
        """Main execution"""
        self.banner()
        
        if not SCAPY_AVAILABLE:
            print(f"{Colors.FAIL}[-] Scapy not available{Colors.ENDC}")
            return
        
        try:
            self.start_capture()
        except KeyboardInterrupt:
            self.running = False
            print(f"\n{Colors.WARNING}[!] Capture stopped{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] Error: {e}{Colors.ENDC}")
        finally:
            self.generate_report()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
    parser.add_argument("--interface", help="Network interface")
    parser.add_argument("--duration", type=int, default=0, help="Capture duration in seconds")
    parser.add_argument("--output", default="traffic_report.html", help="HTML report file")
    
    args = parser.parse_args()
    
    analyzer = TrafficAnalyzer(
        interface=args.interface,
        duration=args.duration,
        output_file=args.output
    )
    
    analyzer.run()

if __name__ == "__main__":
    main()