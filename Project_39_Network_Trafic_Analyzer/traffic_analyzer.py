#!/usr/bin/env python3
"""
Project #39: Real-time Network Traffic Analyzer & Intrusion Detection System
Architecture: Scapy Sniffer + Multithreaded Live Stats Terminal Dashboard.
"""

import os
import sys
import time
import threading
from collections import Counter
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw
except ImportError:
    print("[-] Dependency Missing: Run 'sudo pip3 install scapy'")
    sys.exit(1)

# Color Map
G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"; C = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

# Live Monitoring Global States
packet_count = 0
protocol_counts = Counter()
ip_source_counts = Counter()
ip_dest_counts = Counter()
syn_packet_timestamps = []
anomalies = []
stop_monitoring = False

# Operational Lock for thread safety
lock = threading.Lock()

def analyze_packet(packet):
    """Processes raw packet frames and extracts protocol header configurations."""
    global packet_count, syn_packet_timestamps
    
    if not packet.haslayer(IP):
        return

    with lock:
        packet_count += 1
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Track IPs
        ip_source_counts[src_ip] += 1
        ip_dest_counts[dst_ip] += 1
        
        # Protocol Distribution Parsing
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            
            # Identify standard port routing profiles
            if dport == 80 or sport == 80:
                protocol_counts["HTTP (TCP/80)"] += 1
            elif dport == 443 or sport == 443:
                protocol_counts["HTTPS (TCP/443)"] += 1
            elif dport == 22 or sport == 22:
                protocol_counts["SSH (TCP/22)"] += 1
            else:
                protocol_counts["Other TCP"] += 1

            # Anomaly Tracking: SYN Flood Check
            # Flags = 'S' represents connection synchronization requests
            if packet[TCP].flags == 'S':
                current_time = time.time()
                syn_packet_timestamps.append(current_time)
                
                # Filter timestamps to keep only those within the last 1 second
                syn_packet_timestamps = [t for t in syn_packet_timestamps if current_time - t <= 1.0]
                
                if len(syn_packet_timestamps) > 50: # Threshold for high-density validation
                    alert_msg = f"[ALERT] SYN Flood pattern detected from {src_ip} -> {len(syn_packet_timestamps)} SYN/sec"
                    if alert_msg not in anomalies:
                        anomalies.append(alert_msg)

        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            
            if packet.haslayer(DNS) or dport == 53 or sport == 53:
                protocol_counts["DNS (UDP/53)"] += 1
            else:
                protocol_counts["Other UDP"] += 1
                
        elif packet.haslayer(ICMP):
            protocol_counts["ICMP (Ping)"] += 1
        else:
            protocol_counts["Other IP"] += 1

def run_traffic_simulator():
    """Generates synthetic network streams on local loopback for lab verification."""
    print(f"[*] Starting local background traffic simulator engine...")
    # Delay initialization to let the sniffer socket bind first
    time.sleep(2)
    
    import socket
    loopback = "127.0.0.1"
    
    while not stop_monitoring:
        try:
            # Simulate DNS query traffic (UDP)
            sock_dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock_dns.sendto(b"\x00\x01\x01\x00\x00\x01\x00\x00", (loopback, 53))
            sock_dns.close()

            # Simulate HTTP handshake connection (TCP)
            sock_http = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_http.settimeout(0.1)
            sock_http.connect_ex((loopback, 80))
            sock_http.close()
            
            time.sleep(0.2)
        except Exception:
            pass

def draw_dashboard(duration):
    """Refreshes the terminal UI block dynamically to show running metrics."""
    start_time = time.time()
    
    while not stop_monitoring:
        elapsed = int(time.time() - start_time)
        if elapsed >= duration:
            break
            
        # Clean terminal clear
        os.system('clear')
        
        with lock:
            print("======================================================================")
            print(f"  📡  LIVE REAL-TIME TRAFFIC ANALYZER DASHBOARD (Linux Native Mode)")
            print(f"      Time Elapsed: {elapsed}/{duration}s | Total Sniffed: {packet_count}")
            print("======================================================================")
            
            # 1. Print Protocol Distribution
            print(f"\n{C}[+] PROTOCOL DISTRIBUTION STATISTICS:{RESET}")
            print("-" * 50)
            if not protocol_counts:
                print("   Gathering stream metrics...")
            for proto, count in protocol_counts.items():
                pct = (count / packet_count) * 100 if packet_count > 0 else 0
                bar = "█" * int(pct / 10)
                print(f"   {proto:<16} : {count:<5} ({pct:.1f}%) {Y}{bar}{RESET}")
                
            # 2. Print Top Talkers
            print(f"\n{C}[+] TOP TALKING HOSTS (IP SOURCES):{RESET}")
            print("-" * 50)
            for ip, count in ip_source_counts.most_common(3):
                print(f"   IP Address: {G}{ip:<15}{RESET} -> Transmitted Packets: {count}")

            # 3. Print Active Security Anomalies
            print(f"\n{R}[!] LIVE INTRUSION ALERTS & ANOMALIES:{RESET}")
            print("-" * 50)
            if not anomalies:
                print(f"   {G}[✓] No anomalous activity patterns matched.{RESET}")
            else:
                for alert in anomalies[-3:]:
                    print(f"   {R}{alert}{RESET}")
            print("======================================================================")
            
        time.sleep(1)

def generate_html_report():
    """Compiles the captured metrics into an inspection HTML report."""
    html = f"""
    <html>
    <head><title>Network Traffic Analysis Report</title>
    <style>body{{font-family:monospace;background:#111;color:#eee;padding:25px;}}th,td{{padding:10px;border:1px solid #333;}}</style></head>
    <body>
        <h2>🎯 Production Network Analysis & Forensics Summary</h2>
        <p>Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <hr style="border-color:#333;">
        <h3>Total Packets Captured: {packet_count}</h3>
        
        <h4>1. Protocol Distribution Matrix</h4>
        <table border="1" style="border-collapse:collapse; width:50%;">
            <tr style="background:#222;"><th>Protocol Profile</th><th>Count</th></tr>
    """
    for proto, count in protocol_counts.items():
        html += f"<tr><td>{proto}</td><td>{count}</td></tr>"
    html += """
        </table>
        
        <h4>2. Active Alerts Logged</h4>
        <ul>
    """
    if not anomalies:
        html += "<li>No critical security threshold breaches identified during active window runtime.</li>"
    else:
        for alert in anomalies:
            html += f"<li style='color:red;'>{alert}</li>"
            
    html += """
        </ul>
    </body>
    </html>
    """
    with open("traffic_summary_report.html", "w") as f:
        f.write(html)
    print(f"\n[+] Interactive summary report exported successfully: {G}traffic_summary_report.html{RESET}\n")

def main():
    global stop_monitoring
    parser = argparse.ArgumentParser(description="Live Native Linux Packet Auditing System")
    parser.add_argument("--interface", required=True, help="Network interface to sniff (e.g., lo, wlan0, eth0)")
    parser.add_argument("--duration", type=int, default=15, help="Sniffing window time limit in seconds")
    args = parser.parse_args()

    # Verify Root Privileges for raw socket manipulation
    if os.geteuid() != 0:
        print(f"\n{R}[!] Access Blocked: Packet sniffing requires raw socket privileges.{RESET}")
        print(f"    👉 Re-run execution using: {Y}sudo python3 traffic_analyzer.py --interface {args.interface}{RESET}\n")
        sys.exit(1)

    # Spawn local traffic generator on loopback interface to verify detection runs smoothly
    sim_thread = None
    if args.interface == "lo":
        sim_thread = threading.Thread(target=run_traffic_simulator, daemon=True)
        sim_thread.start()

    # Spawn real-time UI dashboard display thread
    ui_thread = threading.Thread(target=draw_dashboard, args=(args.duration,), daemon=True)
    ui_thread.start()

    print(f"[*] Initializing Scapy sniffing socket over interface '{args.interface}'...")
    try:
        # Sniff packets natively using socket interfaces
        sniff(iface=args.interface, prn=analyze_packet, timeout=args.duration, store=False)
    except Exception as e:
        print(f"\n{R}[!] Scapy socket connection dropped: {e}{RESET}")
    finally:
        stop_monitoring = True
        if sim_thread:
            sim_thread.join(timeout=1)
        ui_thread.join(timeout=1)
        
    generate_html_report()

if __name__ == "__main__":
    import argparse
    main()
