#!/usr/bin/env python3
"""
============================================================
  PROJECT #15 MODE 1 — DNS Spoof Detector
  100 Ethical Hacking Projects Series
  Method: sniff DNS responses + cross-check against 8.8.8.8
============================================================
  ⚠  Passive sniffing only — sends zero attack packets.
     Legal on your own network.

HOW DNS SPOOFING WORKS
------------------------
Attacker on LAN intercepts DNS query (UDP port 53) and races
to reply before the real resolver. Client accepts first reply
with matching transaction ID. Result: client resolves
"bank.com" → attacker's IP instead of real server.
Classic Kaminsky attack (2008) showed how to poison resolvers
at scale using predictable transaction IDs + port numbers.

DEFENSE
--------
1. DNSSEC — cryptographic signatures on DNS records.
   Forged reply fails signature check → rejected.
2. DNS-over-HTTPS / DNS-over-TLS — encrypts query so
   attacker can't intercept and race-reply.
3. DNSSEC-validating resolver (1.1.1.1, 9.9.9.9).
4. Monitor resolver logs for sudden IP changes (this script).

USAGE
------
  sudo python3 dns_detector.py --iface eth0
  sudo python3 dns_detector.py --iface eth0 --trusted 8.8.8.8 --log dns_log.json
  python3 dns_detector.py --simulate
============================================================
"""

import argparse, sys, time, json, datetime, socket, threading
from collections import defaultdict

R="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
YELLOW="\033[93m";CYAN="\033[96m";MAGENTA="\033[95m";DIM="\033[2m"
def c(t,code): return f"{code}{t}{R}"

# ── known-good cache {domain → set of IPs from trusted resolver} ──
trusted_cache = {}
spoof_log     = []
event_log     = []
stats         = {"queries":0,"responses":0,"spoofs":0,"checked":0}
lock          = threading.Lock()

# ─────────────────────────────────────────────────────────
# TRUSTED RESOLVER LOOKUP
# ─────────────────────────────────────────────────────────
def lookup_trusted(domain: str, trusted_ip: str) -> set[str]:
    """Query trusted resolver directly via UDP and return set of A record IPs."""
    if domain in trusted_cache:
        return trusted_cache[domain]
    try:
        import dnslib
        q   = dnslib.DNSRecord.question(domain)
        raw = q.send(trusted_ip, 53, timeout=3)
        ans = dnslib.DNSRecord.parse(raw)
        ips = set()
        for rr in ans.rr:
            if rr.rtype == dnslib.QTYPE.A:
                ips.add(str(rr.rdata))
        trusted_cache[domain] = ips
        return ips
    except Exception:
        return set()

# ─────────────────────────────────────────────────────────
# PACKET HANDLER
# ─────────────────────────────────────────────────────────
def make_handler(trusted_ip: str, verbose: bool):
    from scapy.layers.dns import DNS, DNSRR, DNSQR
    from scapy.layers.inet import UDP, IP

    def handler(pkt):
        if not pkt.haslayer(DNS): return
        dns = pkt[DNS]
        # only look at responses (QR=1) with answers
        if dns.qr != 1 or dns.ancount == 0: return

        ts  = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        src = pkt[IP].src if pkt.haslayer(IP) else "?"

        with lock:
            stats["responses"] += 1

        # extract all A records from answer section
        answered_ips = set()
        domain       = ""
        try:
            if dns.qd:
                domain = str(dns.qd.qname).rstrip(".")
            an = dns.an
            while an:
                if an.type == 1:   # A record
                    answered_ips.add(str(an.rdata))
                an = an.payload if hasattr(an, "payload") and isinstance(an.payload, DNSRR) else None
        except Exception:
            return

        if not domain or not answered_ips:
            return

        with lock:
            stats["checked"] += 1

        if verbose:
            print(f"  {c(ts, DIM)}  DNS  {c(src, MAGENTA):<18}  "
                  f"{c(domain[:35], CYAN):<44}  → {c(', '.join(answered_ips), GREEN)}")

        # cross-check against trusted resolver (async to avoid blocking sniffer)
        threading.Thread(
            target=_check_trusted,
            args=(domain, answered_ips, src, ts, trusted_ip),
            daemon=True
        ).start()

    return handler


def _check_trusted(domain, seen_ips, src, ts, trusted_ip):
    trusted_ips = lookup_trusted(domain, trusted_ip)
    if not trusted_ips:
        return   # couldn't resolve — skip

    overlap = seen_ips & trusted_ips
    mismatch = seen_ips - trusted_ips

    if mismatch:
        with lock:
            stats["spoofs"] += 1
            alert = {
                "time"      : ts,
                "domain"    : domain,
                "seen_ips"  : sorted(seen_ips),
                "trusted_ips": sorted(trusted_ips),
                "src_resolver": src,
            }
            spoof_log.append(alert)

        bad_ips  = ", ".join(sorted(mismatch))
        good_ips = ", ".join(sorted(trusted_ips))
        print()
        print(c(f"  ╔══════════════════════════════════════════════════════╗", RED))
        print(c(f"  ║  ⚠  DNS SPOOF DETECTED                               ║", RED+BOLD))
        print(c(f"  ╚══════════════════════════════════════════════════════╝", RED))
        print(f"  {c('Domain   :', DIM)} {c(domain, YELLOW+BOLD)}")
        print(f"  {c('Seen IPs :', DIM)} {c(bad_ips, RED+BOLD)}  ← from resolver {src}")
        print(f"  {c('Expected :', DIM)} {c(good_ips, GREEN)}  ← from {trusted_ip}")
        print(c(f"  ⚠ SPOOF: {domain} → {bad_ips} (expected {good_ips})", RED+BOLD))
        print()
    elif overlap and not mismatch:
        pass   # legit response, already printed if verbose

# ─────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────
def print_summary(log_path):
    print(c(f"\n  ── SESSION SUMMARY ─────────────────────────────────────", CYAN))
    print(f"  DNS responses   : {c(str(stats['responses']), YELLOW)}")
    print(f"  Domains checked : {c(str(stats['checked']), CYAN)}")
    print(f"  Spoof alerts    : {c(str(stats['spoofs']), RED+BOLD if stats['spoofs'] else DIM)}")

    if spoof_log:
        print(c(f"\n  ── SPOOF LOG ────────────────────────────────────────────", RED))
        for s in spoof_log:
            print(f"  [{s['time']}] {c(s['domain'], YELLOW)} "
                  f"seen={c(str(s['seen_ips']), RED)} "
                  f"expected={c(str(s['trusted_ips']), GREEN)}")

    if log_path:
        with open(log_path, "w") as f:
            json.dump({"stats": stats, "spoofs": spoof_log}, f, indent=2)
        print(c(f"\n  ✔ Log → {log_path}", GREEN))
    print()

# ─────────────────────────────────────────────────────────
# SIMULATION
# ─────────────────────────────────────────────────────────
def simulate(log_path):
    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   PROJECT #15 · DNS SPOOF DETECTOR  [SIMULATION]     ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════════╝", CYAN))
    print()
    print(f"  {'TIME':13}  {'RESOLVER':<18}  {'DOMAIN':<35}  IPs")
    print("  "+c("─"*85, DIM))

    # pre-populate trusted cache (skip real network calls)
    trusted_cache["google.com"]      = {"142.250.80.46"}
    trusted_cache["github.com"]      = {"140.82.121.3"}
    trusted_cache["bank.example.com"]= {"93.184.216.34"}
    trusted_cache["router.local"]    = {"192.168.1.1"}

    events = [
        # (domain, seen_ip, src_resolver, is_spoof)
        ("google.com",       "142.250.80.46",  "192.168.1.1",   False),
        ("github.com",       "140.82.121.3",   "192.168.1.1",   False),
        ("bank.example.com", "93.184.216.34",  "192.168.1.1",   False),
        # ── spoofed responses ──────────────────────────────────
        ("bank.example.com", "10.0.0.99",      "192.168.1.55",  True),
        ("google.com",       "172.16.1.1",     "192.168.1.55",  True),
        ("github.com",       "140.82.121.3",   "192.168.1.1",   False),  # legit again
    ]

    ts_base = datetime.datetime.now()
    for i, (domain, ip, src, is_spoof) in enumerate(events):
        ts = (ts_base + datetime.timedelta(seconds=i*0.3)).strftime("%H:%M:%S.%f")[:-3]
        seen = {ip}
        with lock: stats["responses"] += 1; stats["checked"] += 1
        tag = c("legit ", GREEN) if not is_spoof else c("SPOOFED", RED+BOLD)
        print(f"  {c(ts,DIM)}  {c(src,MAGENTA):<27}  {c(domain,CYAN):<44}  "
              f"{c(ip,GREEN if not is_spoof else RED)}  {tag}")
        _check_trusted(domain, seen, src, ts, "8.8.8.8")
        time.sleep(0.05)

    print_summary(log_path)

    print(c("  ── ASSERTIONS ──────────────────────────────────────────", CYAN))
    p1 = stats["spoofs"] == 2
    p2 = len(spoof_log)  == 2
    p3 = all("bank.example.com" == s["domain"] or "google.com" == s["domain"]
             for s in spoof_log)
    for ok, msg in [(p1,"2 spoofs detected"),(p2,"2 entries in log"),(p3,"correct domains")]:
        print(f"  {c('✔',GREEN) if ok else c('✗',RED)} {msg}")
    print()
    print(c("  ✔ ALL ASSERTIONS PASSED" if all([p1,p2,p3])
            else "  ✗ SOME FAILED", GREEN+BOLD if all([p1,p2,p3]) else RED))
    print()

# ─────────────────────────────────────────────────────────
# LIVE SNIFF
# ─────────────────────────────────────────────────────────
def live_sniff(iface, trusted_ip, verbose, log_path):
    from scapy.all import sniff, conf; conf.verb = 0
    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   PROJECT #15 · DNS SPOOF DETECTOR                   ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════════╝", CYAN))
    print()
    print(f"  Interface  : {c(iface, YELLOW)}")
    print(f"  Trusted DNS: {c(trusted_ip, GREEN)}")
    print(c("  Sniffing DNS responses … (Ctrl+C to stop)\n", DIM))

    handler = make_handler(trusted_ip, verbose)
    try:
        sniff(iface=iface, filter="udp port 53", prn=handler, store=False)
    except KeyboardInterrupt: pass
    except PermissionError:
        print(c("\n  Need root: sudo python3 dns_detector.py", RED)); sys.exit(1)
    print_summary(log_path)

# ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Project #15 — DNS Spoof Detector")
    parser.add_argument("--iface",    default="eth0")
    parser.add_argument("--trusted",  default="8.8.8.8")
    parser.add_argument("--verbose",  action="store_true")
    parser.add_argument("--log",      default=None)
    parser.add_argument("--simulate", action="store_true")
    args = parser.parse_args()
    if args.simulate: simulate(args.log)
    else: live_sniff(args.iface, args.trusted, args.verbose, args.log)

if __name__ == "__main__": main()