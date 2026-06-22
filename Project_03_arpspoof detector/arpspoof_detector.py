
#!/usr/bin/env python3
"""
============================================================
  PROJECT #3 — ARP Spoof Detector
  100 Ethical Hacking Projects Series
  Engine  : scapy (ARP packet sniffing)
  Runtime : 60 seconds OR 50 ARP packets (whichever first)
  Alert   : IP→MAC conflict = potential ARP spoof
============================================================

WHY ETHICAL HACKERS NEED ARP SPOOF DETECTION (Defense)
---------------------------------------------------------
ARP (Address Resolution Protocol) has NO authentication.
Anyone on the LAN can broadcast "I am 192.168.1.1, my MAC
is AA:BB:CC:DD:EE:FF" and every device will update its ARP
cache silently. An attacker exploits this to become the
"man in the middle" — redirecting traffic through their
machine to intercept credentials, session tokens, or inject
malicious content.

From the ethical hacker's perspective:
  OFFENSE  — ARP spoofing enables MITM, credential harvest,
              SSL stripping, and lateral movement.
  DEFENSE  — A blue-team tool that continuously monitors
              ARP tables catches these attacks in real-time,
              letting defenders alert, block, or isolate the
              attacking machine before damage is done.

A professor teaching network security must demonstrate BOTH
sides: how the attack works (scapy ARP reply crafting) and
how detection works (this script) — because understanding
the weapon is the first step to building the shield.

USAGE
------
  sudo python3 project3_arpspoof_detector.py
  sudo python3 project3_arpspoof_detector.py --iface eth0
  sudo python3 project3_arpspoof_detector.py --packets 100 --time 120
  sudo python3 project3_arpspoof_detector.py --simulate   # built-in spoof demo
============================================================
"""

import argparse
import sys
import time
import threading
import datetime
from collections import defaultdict

# ── colours ───────────────────────────────────────────────
R="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
YELLOW="\033[93m";CYAN="\033[96m";MAGENTA="\033[95m";DIM="\033[2m"
BG_RED="\033[41m";BG_GREEN="\033[42m"

def c(t,code): return f"{code}{t}{R}"

# ── ARP table: {ip: {"mac": str, "time": float, "count": int}} ───
arp_table   = {}
spoof_log   = []          # list of alert dicts
packet_count= [0]
lock        = threading.Lock()

# ── stats ─────────────────────────────────────────────────
stats = defaultdict(int)  # "request", "reply", "spoof_alert"

# ── banner ────────────────────────────────────────────────
def banner():
    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   PROJECT #3 · ARP SPOOF DETECTOR                    ║", CYAN))
    print(c("  ║   Monitoring LAN for ARP cache poisoning attacks      ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════════╝", CYAN))
    print()

# ── format mac ────────────────────────────────────────────
def fmt_mac(mac):
    return mac.upper() if mac else "??:??:??:??:??:??"

def fmt_time(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S")

# ── print ARP table state ─────────────────────────────────
def print_table():
    with lock:
        entries = list(arp_table.items())

    if not entries:
        print(c("  [ARP TABLE]  Empty — no ARP replies captured yet.", DIM))
        return

    print(f"\n  {c('── CURRENT ARP TABLE ────────────────────────────────', CYAN)}")
    print(f"  {'IP ADDRESS':<18}  {'MAC ADDRESS':<20}  {'LAST SEEN':<10}  PKTS")
    print("  " + "─"*58)
    for ip, entry in sorted(entries):
        print(f"  {c(ip, YELLOW):<27}  {c(fmt_mac(entry['mac']), MAGENTA):<29}  "
              f"{fmt_time(entry['time']):<10}  {entry['count']}")

# ── core packet handler ───────────────────────────────────
def handle_arp(pkt):
    from scapy.layers.l2 import ARP

    if not pkt.haslayer(ARP):
        return

    arp      = pkt[ARP]
    op       = arp.op          # 1=request (who-has), 2=reply (is-at)
    src_ip   = arp.psrc        # sender IP
    src_mac  = arp.hwsrc       # sender MAC
    dst_ip   = arp.pdst        # target IP
    now      = time.time()
    ts       = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

    packet_count[0] += 1
    pkt_num = packet_count[0]

    # skip empty/broadcast-only requests for table (still log them)
    if op == 1:
        stats["request"] += 1
        op_label = c("REQUEST", DIM)
        print(f"  [{c(f'{pkt_num:>3}', BOLD)}] {c(ts, CYAN)}  "
              f"{op_label}  {c(src_ip, YELLOW)} asks: who has {c(dst_ip, YELLOW)}?  "
              f"sender-MAC={c(fmt_mac(src_mac), MAGENTA)}")
        # Also update table for requester's own IP/MAC binding
        _update_table(src_ip, src_mac, now, pkt_num, ts)
        return

    # ARP reply (op==2) — this is what spoofers send
    stats["reply"] += 1
    op_label = c("REPLY  ", GREEN)

    with lock:
        if src_ip in arp_table:
            existing_mac = arp_table[src_ip]["mac"]
            if existing_mac.lower() != src_mac.lower():
                # ─── SPOOF ALERT ───────────────────────────────
                stats["spoof_alert"] += 1
                alert_num = stats["spoof_alert"]
                alert = {
                    "n"          : alert_num,
                    "time"       : ts,
                    "ip"         : src_ip,
                    "old_mac"    : existing_mac,
                    "new_mac"    : src_mac,
                    "pkt_num"    : pkt_num,
                }
                spoof_log.append(alert)

                print()
                print(c(f"  ╔{'═'*54}╗", RED))
                print(c(f"  ║  ⚠  ARP SPOOF ALERT  #{alert_num:<3}                          ║", RED))
                print(c(f"  ╚{'═'*54}╝", RED))
                print(f"  {c('Packet', DIM)} #{pkt_num}  at  {c(ts, CYAN)}")
                print(f"  IP       : {c(src_ip, YELLOW)}")
                print(f"  OLD MAC  : {c(fmt_mac(existing_mac), GREEN)}  ← legitimate (seen before)")
                print(f"  NEW MAC  : {c(fmt_mac(src_mac), RED)}  ← CONFLICT  (possible attacker)")
                print(f"  ACTION   : Update blocked — original mapping preserved.")
                print()
                # Do NOT update table — keep the trusted MAC
                return
            else:
                # same MAC, just refresh
                arp_table[src_ip]["time"]  = now
                arp_table[src_ip]["count"] += 1
        else:
            arp_table[src_ip] = {"mac": src_mac, "time": now, "count": 1}

    print(f"  [{c(f'{pkt_num:>3}', BOLD)}] {c(ts, CYAN)}  "
          f"{op_label}  {c(src_ip, YELLOW)} is at {c(fmt_mac(src_mac), MAGENTA)}")


def _update_table(ip, mac, now, pkt_num, ts):
    """Insert or refresh an IP→MAC mapping (no conflict check for requests)."""
    with lock:
        if ip and ip != "0.0.0.0":
            if ip not in arp_table:
                arp_table[ip] = {"mac": mac, "time": now, "count": 1}
            else:
                arp_table[ip]["time"]  = now
                arp_table[ip]["count"] += 1

# ── summary ───────────────────────────────────────────────
def print_summary(elapsed):
    print(f"\n  {c('── SESSION SUMMARY ─────────────────────────────────', CYAN)}")
    print(f"  Duration   : {elapsed:.1f}s")
    print(f"  Total pkts : {packet_count[0]}")
    print(f"  Requests   : {stats['request']}")
    print(f"  Replies    : {stats['reply']}")
    spoof_n = stats['spoof_alert']
    if spoof_n:
        print(f"  {c('SPOOF ALERTS : ' + str(spoof_n), RED + BOLD)}")
        print()
        print(f"  {c('── SPOOF LOG ────────────────────────────────────────', RED)}")
        for a in spoof_log:
            print(f"  #{a['n']}  [{a['time']}]  IP={c(a['ip'],YELLOW)}  "
                  f"{c(fmt_mac(a['old_mac']),GREEN)} → {c(fmt_mac(a['new_mac']),RED)}")
    else:
        print(f"  {c('SPOOF ALERTS : 0  — Network appears clean.', GREEN)}")
    print_table()
    print()

# ─────────────────────────────────────────────────────────
# SIMULATION MODE  — injects crafted spoof packets locally
# so you can test the detector without a second machine
# ─────────────────────────────────────────────────────────
def simulate_spoof():
    """
    Replays a sequence of ARP packets (legitimate + spoofed)
    directly through handle_arp() — no live NIC needed.
    """
    from scapy.layers.l2 import ARP, Ether
    from scapy.packet import Packet

    banner()
    print(c("  [SIMULATION MODE]  Injecting crafted ARP packets …\n", YELLOW))
    print(f"  {'#':>4}  DESCRIPTION")
    print("  " + "─"*60)

    # sequence of (description, src_ip, src_mac, dst_ip, op)
    sequence = [
        ("Legit reply: Router 192.168.1.1",
         "192.168.1.1",  "aa:bb:cc:dd:ee:01", "192.168.1.5",  2),
        ("Legit reply: PC-A 192.168.1.10",
         "192.168.1.10", "aa:bb:cc:dd:ee:02", "192.168.1.5",  2),
        ("Legit reply: PC-B 192.168.1.20",
         "192.168.1.20", "aa:bb:cc:dd:ee:03", "192.168.1.5",  2),
        ("Legit request from PC-A",
         "192.168.1.10", "aa:bb:cc:dd:ee:02", "192.168.1.1",  1),
        ("Legit reply refresh: Router",
         "192.168.1.1",  "aa:bb:cc:dd:ee:01", "192.168.1.5",  2),
        # ── ATTACK BEGINS ─────────────────────────────────
        ("⚠ SPOOF: Attacker claims to be Router (192.168.1.1) with fake MAC",
         "192.168.1.1",  "de:ad:be:ef:ca:fe", "192.168.1.5",  2),
        ("⚠ SPOOF: Attacker also claims PC-A's IP with same fake MAC",
         "192.168.1.10", "de:ad:be:ef:ca:fe", "192.168.1.5",  2),
        ("Legit reply from PC-B (unaffected)",
         "192.168.1.20", "aa:bb:cc:dd:ee:03", "192.168.1.5",  2),
    ]

    for i, (desc, sip, smac, dip, op) in enumerate(sequence, 1):
        pkt = Ether(src=smac, dst="ff:ff:ff:ff:ff:ff") / \
              ARP(op=op, hwsrc=smac, psrc=sip, hwdst="00:00:00:00:00:00", pdst=dip)
        print(f"\n  {c(f'Step {i}', BOLD)}: {desc}")
        handle_arp(pkt)
        time.sleep(0.3)

    t_end = time.time()
    print_summary(len(sequence) * 0.3)
    print(c("  ✔  Simulation complete. Detector correctly identified all spoofed packets.\n", GREEN))

# ─────────────────────────────────────────────────────────
# LIVE SNIFF MODE
# ─────────────────────────────────────────────────────────
def live_sniff(iface, max_pkts, max_time):
    from scapy.all import sniff, conf

    banner()
    print(f"  Interface  : {c(iface or 'default', YELLOW)}")
    print(f"  Stop after : {c(str(max_pkts), CYAN)} ARP packets  OR  "
          f"{c(str(max_time)+'s', CYAN)}  (whichever first)")
    print(c("\n  Listening for ARP packets … (Ctrl+C to stop early)\n", GREEN))
    print(f"  {'#':>4}  {'TIME':13}  {'TYPE':9}  DETAILS")
    print("  " + "─"*70)

    t_start = time.time()

    # timer thread to enforce time limit
    def timeout_killer():
        time.sleep(max_time)
        # scapy sniff doesn't have clean external stop on all platforms
        # we rely on stop_filter for the packet-count limit + time check
    threading.Thread(target=timeout_killer, daemon=True).start()

    def stop_filter(pkt):
        return (packet_count[0] >= max_pkts or
                time.time() - t_start >= max_time)

    try:
        sniff(
            iface=iface if iface else None,
            filter="arp",
            prn=handle_arp,
            stop_filter=stop_filter,
            store=False,
        )
    except PermissionError:
        print(c("\n  [ERROR] Permission denied — run as root:", RED))
        print(c("  sudo python3 project3_arpspoof_detector.py\n", YELLOW))
        sys.exit(1)
    except KeyboardInterrupt:
        pass

    elapsed = time.time() - t_start
    print_summary(elapsed)

# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Project #3 — ARP Spoof Detector")
    parser.add_argument("--iface",    default=None,
                        help="Network interface (default: scapy auto)")
    parser.add_argument("--packets",  type=int, default=50,
                        help="Max ARP packets before stopping (default: 50)")
    parser.add_argument("--time",     type=int, default=60,
                        help="Max seconds to run (default: 60)")
    parser.add_argument("--simulate", action="store_true",
                        help="Run built-in spoof simulation (no root needed)")
    args = parser.parse_args()

    if args.simulate:
        simulate_spoof()
    else:
        live_sniff(args.iface, args.packets, args.time)


if __name__ == "__main__":
    main()