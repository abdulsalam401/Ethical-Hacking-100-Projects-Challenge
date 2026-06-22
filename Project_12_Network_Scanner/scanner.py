#!/usr/bin/env python3
"""
Project #12: Network Scanner with Passive OS Fingerprinting (Nmap-style)
Architecture: Scapy-crafted L2 ARP Broadcasts + L4 TCP SYN Probes.
"""

import sys
import time
import json
import argparse
from concurrent.futures import ThreadPoolExecutor
import logging

# Mute Scapy stderr runtime warning logs at startup
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    from scapy.all import ARP, Ether, srp, IP, TCP, sr1
except ImportError:
    print("[-] Missing dependency: Run pip3 install scapy")
    sys.exit(1)

# --- Terminal Coloring Blueprint ---
G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"; R = "\033[91m"; BOLD = "\033[1m"; RESET = "\033[0m"

TOP_20_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
TOP_5_PORTS = [22, 80, 139, 443, 445]

PORT_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Proxy"
}

def fingerprint_os(ttl: int, window: int) -> str:
    """Infers the host operating system based on default IP stack signatures."""
    if ttl is None:
        return "Unknown (No Response)"
    
    # Standard normalization for network hops that decrement TTL values along paths
    if ttl <= 64:
        if window == 65535:
            return "macOS / iOS"
        return "Linux / Android"
    elif ttl <= 128:
        return "Windows NT/10/11"
    elif ttl <= 255:
        return "Solaris / Cisco iOS"
    return f"Unknown (TTL: {ttl} | Win: {window})"

def arp_discovery(subnet: str) -> list:
    """Discovers live active hosts inside the target network mask using ARP frames."""
    print(f"[*] Initiating Layer-2 ARP Discovery across: {subnet}")
    live_hosts = []
    try:
        # Craft L2 Broadcast Ethernet wrapper + L2 Target ARP Payload
        ether_packet = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_packet = ARP(pdst=subnet)
        broadcast_frame = ether_packet / arp_packet

        # Transmit frame pool and gather answered array
        answered, _ = srp(broadcast_frame, timeout=3, verbose=False)
        
        for send, recv in answered:
            live_hosts.append({"ip": recv.psrc, "mac": recv.hwsrc})
    except Exception as e:
        print(f"{R}[!] Discovery Phase Failure: Check privileges (sudo required) -> {e}{RESET}")
        sys.exit(1)
        
    return live_hosts

def scan_single_port(ip: str, port: int, delay: float) -> dict:
    """Performs an isolated TCP SYN Stealth Scan probe on a specified target socket."""
    if delay > 0:
        time.sleep(delay)
        
    try:
        # Craft raw Layer-3 IP router packet mapped into a Layer-4 TCP SYN frame flags=S
        syn_probe = IP(dst=ip) / TCP(sport=34822, dport=port, flags="S")
        response = sr1(syn_probe, timeout=1.0, verbose=False)
        
        if response and response.haslayer(TCP):
            tcp_layer = response.getlayer(TCP)
            ip_layer = response.getlayer(IP)
            
            # Look for SYN-ACK indicators (flags=0x12 -> SYN=2 + ACK=16)
            if tcp_layer.flags == 0x12:
                # Send RST packet immediately down line to close connection cleanly (Teardown)
                rst_packet = IP(dst=ip) / TCP(sport=34822, dport=port, flags="R")
                sr1(rst_packet, timeout=0.5, verbose=False)
                return {"port": port, "status": "open", "ttl": ip_layer.ttl, "window": tcp_layer.window}
    except Exception:
        pass
    return {"port": port, "status": "closed", "ttl": None, "window": None}

def assess_host(host: dict, ports: list, delay: float) -> dict:
    """Orchestrates parallel port testing against a discovered node target."""
    ip = host["ip"]
    print(f"[*] Profiling host {ip} across {len(ports)} target ports...")
    
    open_ports = []
    detected_ttl = None
    detected_window = None

    # Implement ThreadPoolExecutor to accelerate SYN flag scanning safely
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(scan_single_port, ip, p, delay) for p in ports]
        for future in futures:
            res = future.result()
            if res["status"] == "open":
                open_ports.append(res["port"])
                # Capture signature parameters from open socket responses
                if res["ttl"] is not None:
                    detected_ttl = res["ttl"]
                    detected_window = res["window"]

    # Fallback to high-level ping profile tracking if no ports open up
    if detected_ttl is None:
        try:
            ping_reply = sr1(IP(dst=ip)/TCP(sport=34822, dport=80, flags="S"), timeout=1.0, verbose=False)
            if ping_reply:
                detected_ttl = ping_reply.getlayer(IP).ttl
                if ping_reply.haslayer(TCP):
                    detected_window = ping_reply.getlayer(TCP).window
        except Exception:
            pass

    os_guess = fingerprint_os(detected_ttl, detected_window)
    
    return {
        "ip": ip,
        "mac": host["mac"],
        "open_ports": open_ports,
        "os_guess": os_guess,
        "ttl": detected_ttl,
        "window": detected_window
    }

def main():
    parser = argparse.ArgumentParser(description="Nmap-Style Network Profiler Framework")
    parser.add_argument("--subnet", required=True, help="Target subnet configuration range (e.g. 192.168.1.0/24)")
    parser.add_argument("--fast", action="store_true", help="Scan only the top 5 high-priority ports")
    parser.add_argument("--delay", type=float, default=0.0, help="Enforce packet delay throttling window in seconds")
    parser.add_argument("--output", help="Save final machine-readable results array cleanly to JSON file destination")
    args = parser.parse_args()

    ports_to_scan = TOP_5_PORTS if args.fast else TOP_20_PORTS

    print(f"{C}{BOLD}======================================================================")
    print("  CYBERAUDIT CORE: MULTI-MODE NETWORK PROFILER & OS FINGERPRINTER")
    print(f"======================================================================{RESET}")

    start_time = time.time()
    discovered_nodes = arp_discovery(args.subnet)
    
    if not discovered_nodes:
        print(f"{Y}[-] Reconnaissance phase concluded: 0 active targets identified on interface route.{RESET}")
        return

    print(f"{G}[+] Discovered {len(discovered_nodes)} live network assets. Transitioning to L4 evaluation...{RESET}\n")
    
    final_report = []
    for node in discovered_nodes:
        host_metrics = assess_host(node, ports_to_scan, args.delay)
        final_report.append(host_metrics)

    # --- Render Structured Table Output Display ---
    print(f"\n{BOLD}{C}┌─────────────────┬───────────────────┬──────────────────────┬────────────────────────┐")
    print("│ TARGET IP       │ HARDWARE MAC      │ OPEN SERVICES        │ OS FINGERPRINT GUESS   │")
    print("├─────────────────┼───────────────────┼──────────────────────┼────────────────────────┤")
    for r in final_report:
        ports_str = ", ".join([f"{p}({PORT_MAP.get(p)})" for p in r["open_ports"]]) if r["open_ports"] else "None Located"
        # Truncate strings to prevent wrapping alignment breaks
        ports_str = (ports_str[:20] + "..") if len(ports_str) > 20 else ports_str.ljust(20)
        
        ip_field = r["ip"].ljust(15)
        mac_field = r["mac"].ljust(17)
        os_field = r["os_guess"].ljust(22)
        
        print(f"│ {G}{ip_field}{RESET} │ {mac_field} │ {Y}{ports_str}{RESET} │ {C}{os_field}{RESET} │")
    print(f"└─────────────────┴───────────────────┴──────────────────────┴────────────────────────┘{RESET}")

    duration = time.time() - start_time
    print(f"\n[+] Processing sweep accomplished in {duration:.2f} seconds.")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(final_report, f, indent=4)
        print(f"[+] Output logs exported to disk cleanly at filename: {args.output}")

if __name__ == "__main__":
    main()
