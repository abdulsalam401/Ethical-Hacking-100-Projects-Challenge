#!/usr/bin/env python3
"""
============================================================
  PROJECT #2 — Port Scanner (TCP Connect & SYN Stealth)
  100 Ethical Hacking Projects Series
  Scan range : ports 1–1024
  Methods    : TCP Connect  +  SYN Stealth (scapy)
  Timeout    : 1 second per port
============================================================

WHY ROOT IS REQUIRED FOR SYN SCAN
-----------------------------------
SYN scan forges raw IP/TCP packets via scapy (AF_PACKET /
SOCK_RAW). Crafting packets below the OS TCP stack requires
CAP_NET_RAW on Linux — i.e. root. TCP Connect scan works
without root because it uses the normal socket API.

REAL-WORLD SCENARIO: SYN vs TCP Connect
-----------------------------------------
Intrusion Detection Systems (IDS) like Snort trigger on
completed TCP handshakes — they log the full 3-way SYN →
SYN-ACK → ACK sequence as a new connection. A SYN scan
(half-open) drops the connection after SYN-ACK, never
sending ACK or RST via the OS stack, so it leaves NO entry
in the server's established-connections table and evades
many stateful firewall logs. Penetration testers use SYN
scans to enumerate open ports on a hardened target without
triggering session-based IDS alerts. TCP Connect would log
a completed connection in Apache/nginx access logs and
firewall state tables; SYN scan typically does not.

USAGE
------
  # TCP Connect only (no root needed):
  python3 project2_portscanner.py --target scanme.nmap.org --method tcp

  # SYN scan only (root required):
  sudo python3 project2_portscanner.py --target scanme.nmap.org --method syn

  # Both methods + comparison (root required):
  sudo python3 project2_portscanner.py --target scanme.nmap.org --method both

  # Scan a custom port range:
  sudo python3 project2_portscanner.py --target 192.168.1.1 --start 1 --end 1024
============================================================
"""

import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── colour helpers ────────────────────────────────────────
RESET  = "\033[0m"; BOLD  = "\033[1m"
RED    = "\033[91m"; GREEN = "\033[92m"
YELLOW = "\033[93m"; CYAN  = "\033[96m"
MAGENTA= "\033[95m"; DIM   = "\033[2m"

def c(text, code): return f"{code}{text}{RESET}"

# ── well-known port → service name ───────────────────────
SERVICE = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    67:"DHCP", 68:"DHCP", 69:"TFTP", 80:"HTTP", 110:"POP3",
    111:"RPC", 119:"NNTP", 123:"NTP", 135:"MSRPC", 137:"NetBIOS",
    138:"NetBIOS", 139:"NetBIOS", 143:"IMAP", 161:"SNMP",
    194:"IRC", 389:"LDAP", 443:"HTTPS", 445:"SMB", 465:"SMTPS",
    500:"IKE", 514:"Syslog", 515:"LPD", 587:"SMTP", 631:"IPP",
    636:"LDAPS", 993:"IMAPS", 995:"POP3S", 1080:"SOCKS",
    1433:"MSSQL", 1521:"Oracle", 3306:"MySQL", 3389:"RDP",
    5432:"PostgreSQL", 5900:"VNC", 6379:"Redis", 8080:"HTTP-Alt",
    8443:"HTTPS-Alt", 27017:"MongoDB",
}

def service_name(port):
    return SERVICE.get(port, "unknown")

# ─────────────────────────────────────────────────────────
# METHOD 1 — TCP Connect scan
# ─────────────────────────────────────────────────────────
def tcp_connect_scan(host, port, timeout=1.0):
    """
    Uses socket.connect_ex() — completes the full 3-way handshake.
    Returns True if the port is OPEN.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            return result == 0   # 0 = success = OPEN
    except Exception:
        return False

# ─────────────────────────────────────────────────────────
# METHOD 2 — SYN Stealth scan (half-open)
# ─────────────────────────────────────────────────────────
def syn_scan(host, port, timeout=1.0):
    """
    Sends a raw SYN packet using scapy.
    If a SYN-ACK comes back  → port is OPEN (we do NOT send ACK/RST).
    If a RST-ACK comes back  → port is CLOSED.
    No response              → FILTERED (firewall drop).
    Returns True if OPEN.
    """
    try:
        from scapy.all import IP, TCP, sr1, conf
        conf.verb = 0           # silence scapy output

        pkt = IP(dst=host) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=0)

        if resp is None:
            return False        # no response → filtered
        if resp.haslayer(TCP):
            tcp_flags = resp[TCP].flags
            # SYN-ACK = 0x12 (flags: S+A)
            if tcp_flags & 0x12 == 0x12:
                return True     # OPEN — we intentionally do NOT complete handshake
        return False
    except Exception:
        return False

# ─────────────────────────────────────────────────────────
# Threaded scanner
# ─────────────────────────────────────────────────────────
def run_scan(host, port_range, method="tcp", timeout=1.0, workers=100):
    open_ports = {}
    ports = list(range(port_range[0], port_range[1] + 1))
    total = len(ports)

    scan_fn = tcp_connect_scan if method == "tcp" else syn_scan

    done = [0]
    def scan_one(port):
        result = scan_fn(host, port, timeout)
        done[0] += 1
        # live progress bar
        pct = done[0] / total
        bar = "█" * int(pct * 30) + "░" * (30 - int(pct * 30))
        print(f"\r  {c(bar, CYAN)}  {done[0]}/{total}", end="", flush=True)
        return port, result

    with ThreadPoolExecutor(max_workers=workers) as exe:
        futures = {exe.submit(scan_one, p): p for p in ports}
        for f in as_completed(futures):
            port, is_open = f.result()
            if is_open:
                open_ports[port] = service_name(port)

    print()   # newline after progress bar
    return open_ports

# ─────────────────────────────────────────────────────────
# Pretty printer
# ─────────────────────────────────────────────────────────
def print_results(open_ports, method_label, elapsed):
    tag = c(f"[{method_label}]", MAGENTA)
    print(f"\n  {tag} Results — {c(str(len(open_ports)), BOLD)} open port(s)  "
          f"{c(f'({elapsed:.1f}s)', DIM)}\n")

    if not open_ports:
        print(c("  No open ports found in range.", YELLOW))
        return

    for port in sorted(open_ports):
        svc = open_ports[port]
        label = c(f"Port {port}/tcp", BOLD)
        status = c("OPEN", GREEN)
        svc_tag = c(f"({svc})", CYAN)
        print(f"  {label:<20} : {status}  {svc_tag}")

# ─────────────────────────────────────────────────────────
# Compare two result sets
# ─────────────────────────────────────────────────────────
def compare_results(tcp_ports, syn_ports):
    all_ports = sorted(set(tcp_ports) | set(syn_ports))
    print(f"\n  {c('── COMPARISON TABLE ──────────────────────────────', CYAN)}\n")
    print(f"  {'PORT':<10}  {'SERVICE':<14}  {'TCP-CONNECT':<14}  {'SYN-STEALTH'}")
    print("  " + "─" * 58)
    for p in all_ports:
        tcp_s = c("OPEN", GREEN)  if p in tcp_ports else c("closed", DIM)
        syn_s = c("OPEN", GREEN)  if p in syn_ports else c("closed", DIM)
        svc   = service_name(p)
        print(f"  {p:<10}  {svc:<14}  {tcp_s:<23}  {syn_s}")

    only_tcp = set(tcp_ports) - set(syn_ports)
    only_syn = set(syn_ports) - set(tcp_ports)
    if only_tcp:
        print(f"\n  {c('⚠ Ports found by TCP-Connect only:', YELLOW)} {sorted(only_tcp)}")
        print(f"  {c('  Reason: firewall sends RST after ACK — SYN-ACK not relayed to us.', DIM)}")
    if only_syn:
        print(f"\n  {c('⚠ Ports found by SYN only:', YELLOW)} {sorted(only_syn)}")
        print(f"  {c('  Reason: service resets full-connect but responds to half-open.', DIM)}")
    if not only_tcp and not only_syn:
        print(f"\n  {c('✔ Both methods agree on all ports.', GREEN)}")

# ─────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Project #2 — TCP Connect + SYN Stealth Port Scanner")
    parser.add_argument("--target", default="scanme.nmap.org",
                        help="Target hostname or IP (default: scanme.nmap.org)")
    parser.add_argument("--start",  type=int, default=1,    help="Start port (default: 1)")
    parser.add_argument("--end",    type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("--method", choices=["tcp","syn","both"], default="both",
                        help="Scan method: tcp | syn | both (default: both)")
    parser.add_argument("--timeout",type=float, default=1.0, help="Timeout per port (default: 1s)")
    parser.add_argument("--workers",type=int, default=150,  help="Thread pool size (default: 150)")
    args = parser.parse_args()

    # resolve host
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(c(f"\n  [ERROR] Cannot resolve: {args.target}\n", RED))
        sys.exit(1)

    print()
    print(c("  ╔══════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   PROJECT #2 · PORT SCANNER                      ║", CYAN))
    print(c("  ║   TCP Connect  +  SYN Stealth                    ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════╝", CYAN))
    print()
    print(f"  Target  : {c(args.target, BOLD)}  ({c(target_ip, YELLOW)})")
    print(f"  Range   : ports {args.start}–{args.end}  ({args.end - args.start + 1} ports)")
    print(f"  Method  : {c(args.method.upper(), MAGENTA)}")
    print(f"  Timeout : {args.timeout}s / port   Workers: {args.workers}")
    print()

    tcp_results = syn_results = {}

    # ── TCP Connect ──────────────────────────────────────
    if args.method in ("tcp", "both"):
        print(c("  [TCP-CONNECT]  Scanning …", GREEN))
        t0 = time.time()
        tcp_results = run_scan(target_ip, (args.start, args.end),
                               method="tcp", timeout=args.timeout,
                               workers=args.workers)
        tcp_elapsed = time.time() - t0
        print_results(tcp_results, "TCP-CONNECT", tcp_elapsed)

    # ── SYN Stealth ──────────────────────────────────────
    if args.method in ("syn", "both"):
        try:
            from scapy.all import conf
        except ImportError:
            print(c("\n  [ERROR] scapy not installed. SYN scan unavailable.\n", RED))
            print(c("  Install: pip install scapy\n", YELLOW))
            sys.exit(1)

        print(c("\n  [SYN-STEALTH]  Scanning …", MAGENTA))
        t0 = time.time()
        syn_results = run_scan(target_ip, (args.start, args.end),
                               method="syn", timeout=args.timeout,
                               workers=args.workers)
        syn_elapsed = time.time() - t0
        print_results(syn_results, "SYN-STEALTH", syn_elapsed)

    # ── Comparison ───────────────────────────────────────
    if args.method == "both":
        compare_results(tcp_results, syn_results)

    print()
    print(c("  ─────────────────────────────────────────────────────", DIM))
    print(c("  EDUCATIONAL NOTE:", BOLD))
    print("  SYN scan is preferred over TCP Connect when stealth matters:")
    print("  a half-open scan never completes the handshake, so it avoids")
    print("  creating log entries in the server's connection table, evading")
    print("  many stateful IDS/firewall alerts that trigger only on ACK.")
    print()


if __name__ == "__main__":
    main()