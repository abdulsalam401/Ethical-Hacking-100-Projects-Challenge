#!/usr/bin/env python3
"""
============================================================
  PROJECT #1 — Packet Sniffer Analyzer
  100 Ethical Hacking Projects Series
  Author  : CS Graduate → Professor / Elite Ethical Hacker
  Tool    : Scapy  (fallback: raw socket AF_PACKET)
  Capture : 20 packets then auto-stop
============================================================

WHY ROOT IS REQUIRED
---------------------
Capturing raw network frames requires binding to a network
interface at Layer 2 (Data-Link) or Layer 3 (Network).
On Linux, this uses AF_PACKET (raw socket) or a libpcap
handle — both of which demand CAP_NET_RAW / root privilege.
Without it the OS refuses to hand the process a promiscuous
socket because unrestricted sniffing is a security boundary:
any unprivileged user could silently intercept all traffic.

EDUCATIONAL PURPOSE (one sentence)
------------------------------------
A professor who understands packet sniffing can demonstrate
live how protocols behave on the wire — turning abstract
RFC diagrams into observable, measurable reality for students.
"""

import sys
import datetime

PACKET_LIMIT = 20

# ── colour helpers (ANSI) ─────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
MAGENTA= "\033[95m"

PROTO_COLORS = {
    "ICMP": RED,
    "TCP" : GREEN,
    "UDP" : YELLOW,
    "OTHER": CYAN,
}

def color(text, code):
    return f"{code}{text}{RESET}"

def proto_label(pkt):
    """Return a human-readable protocol label."""
    from scapy.layers.inet import TCP, UDP, ICMP
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    return "OTHER"

# ── packet handler ────────────────────────────────────────
counter = {"n": 0}

def handle_packet(pkt):
    from scapy.layers.inet import IP, TCP, UDP, ICMP

    if not pkt.haslayer(IP):
        return  # skip non-IP frames (ARP, etc.)

    counter["n"] += 1
    n       = counter["n"]
    ip      = pkt[IP]
    proto   = proto_label(pkt)
    c       = PROTO_COLORS.get(proto, CYAN)
    ts      = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

    src_port = dst_port = ""
    if pkt.haslayer(TCP):
        src_port = f":{pkt[TCP].sport}"
        dst_port = f":{pkt[TCP].dport}"
    elif pkt.haslayer(UDP):
        src_port = f":{pkt[UDP].sport}"
        dst_port = f":{pkt[UDP].dport}"

    ttl  = ip.ttl
    size = len(pkt)

    line = (
        f"  [{color(f'{n:>2}', BOLD)}] "
        f"{color(ts, CYAN)}  "
        f"proto={color(f'{proto:<5}', c)}  "
        f"src={color(ip.src + src_port, MAGENTA):<26}  "
        f"dst={color(ip.dst + dst_port, MAGENTA):<26}  "
        f"ttl={ttl:<4} len={size}B"
    )
    print(line)

    # extra detail for ICMP
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        print(f"       └─ ICMP type={icmp.type} code={icmp.code}")

    if counter["n"] >= PACKET_LIMIT:
        print(f"\n{color('  ✔  Reached packet limit of ' + str(PACKET_LIMIT) + '. Stopping capture.', GREEN)}\n")
        sys.exit(0)


# ── raw-socket fallback (no scapy) ───────────────────────
def sniff_raw(limit=PACKET_LIMIT):
    """
    Fallback sniffer using only the standard library.
    Parses Ethernet → IP header manually (no scapy).
    Works on Linux with root; limited protocol detection.
    """
    import socket, struct

    PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(0x0800))   # 0x0800 = IPv4
    print(color(f"  [RAW-SOCKET MODE]  Capturing {limit} IPv4 packets …\n", YELLOW))

    n = 0
    while n < limit:
        raw, _ = sock.recvfrom(65535)
        # Ethernet header = 14 bytes; IP header starts at offset 14
        if len(raw) < 34:
            continue
        ip_header = raw[14:34]
        fields = struct.unpack("!BBHHHBBH4s4s", ip_header)
        proto_num  = fields[6]
        src_ip     = socket.inet_ntoa(fields[8])
        dst_ip     = socket.inet_ntoa(fields[9])
        proto_name = PROTO_MAP.get(proto_num, f"PROTO-{proto_num}")
        c          = PROTO_COLORS.get(proto_name, CYAN)
        ts         = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

        n += 1
        print(
            f"  [{color(f'{n:>2}', BOLD)}] {color(ts, CYAN)}  "
            f"proto={color(f'{proto_name:<5}', c)}  "
            f"src={color(src_ip, MAGENTA):<18}  "
            f"dst={color(dst_ip, MAGENTA)}"
        )

    print(f"\n{color('  ✔  Captured ' + str(limit) + ' packets. Done.', GREEN)}\n")
    sock.close()


# ── main ──────────────────────────────────────────────────
def main():
    print()
    print(color("  ╔══════════════════════════════════════════════╗", CYAN))
    print(color("  ║   PROJECT #1 · PACKET SNIFFER ANALYZER       ║", CYAN))
    print(color("  ║   100 Ethical Hacking Projects Series         ║", CYAN))
    print(color(f"  ║   Capturing first {PACKET_LIMIT} IP packets …              ║", CYAN))
    print(color("  ╚══════════════════════════════════════════════╝", CYAN))
    print()

    # ── try scapy first ──────────────────────────────────
    try:
        from scapy.all import sniff
        print(color("  [SCAPY MODE]  Live capture started. Generate traffic!\n", GREEN))
        print(f"  {'#':>4}  {'TIME':13}  {'PROTO':9}  {'SOURCE':28}  {'DESTINATION':28}  {'TTL / LEN'}")
        print("  " + "─" * 95)
        sniff(filter="ip", prn=handle_packet, count=PACKET_LIMIT, store=False)

    except ImportError:
        print(color("  Scapy not found → falling back to raw sockets.\n", YELLOW))
        print(color("  Install scapy:  pip install scapy\n", YELLOW))
        try:
            sniff_raw(PACKET_LIMIT)
        except PermissionError:
            print(color("\n  [ERROR] Permission denied.", RED))
            print(color("  Run this script as root:  sudo python3 project1_sniffer.py\n", RED))
            sys.exit(1)

    except PermissionError:
        print(color("\n  [ERROR] Permission denied — root required.", RED))
        print(color("  WHY: Raw sockets need CAP_NET_RAW (Linux) or Administrator (Windows).", YELLOW))
        print(color("  FIX: sudo python3 project1_sniffer.py\n", YELLOW))
        sys.exit(1)


if __name__ == "__main__":
    main()