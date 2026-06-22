#!/usr/bin/env python3
"""
============================================================
  PROJECT #12 — Network Scanner with OS Fingerprinting
  100 Ethical Hacking Projects Series
  Methods : ARP scan + ICMP ping + TCP SYN + TTL/Window OS guess
  Output  : coloured table + optional JSON
============================================================
  ⚠  Scan ONLY networks you own or have authorisation to test.

DEFENSE AGAINST NETWORK SCANNING
-----------------------------------
1. NETWORK IDS (Snort/Suricata) — rule fires on SYN to >10
   ports from single IP in <5s. Alert: "portscan detected".
2. FIREWALL EGRESS/INGRESS FILTERING — block ICMP echo-request
   from outside; null-route unused subnets → scanner gets no
   replies, subnet looks dead.
3. PORT KNOCKING — real services hidden behind closed ports;
   open only after specific sequence of connection attempts.
4. HONEYPOT PORTS — open a listener on port 4444/9999.
   Any connection = intruder alert. No legit traffic hits it.
5. ARP WATCH — arpwatch daemon logs IP/MAC mappings; alerts
   on new hosts or MAC changes (also detects ARP spoof).

OS FINGERPRINT LOGIC (TTL + TCP WINDOW)
------------------------------------------
TTL observed at destination ≈ starting TTL minus hops:
  Linux/Android  : starts 64  → 64 or 63 or 62 …
  Windows        : starts 128 → 128 or 127 or 126 …
  Cisco IOS      : starts 255 → 255 or 254 …
  macOS/BSD      : starts 64  (same as Linux, use window to disambiguate)

TCP Window Size (SYN-ACK):
  Linux      : 5840 / 14600 / 29200 / 65535
  Windows 10 : 65535 / 8192
  macOS      : 65535 (with WSCALE option)
  FreeBSD    : 65535

USAGE
------
  sudo python3 project12_scanner.py --subnet 192.168.1.0/24
  sudo python3 project12_scanner.py --subnet 10.0.0.0/24 --fast
  sudo python3 project12_scanner.py --subnet 192.168.1.0/24 --output results.json
  sudo python3 project12_scanner.py --subnet 192.168.1.0/24 --delay 0.2
  python3 project12_scanner.py --simulate          # demo without root/network
============================================================
"""

import argparse, sys, os, json, time, socket, struct
import ipaddress, datetime, threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── colours ───────────────────────────────────────────────
R="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
YELLOW="\033[93m";CYAN="\033[96m";MAGENTA="\033[95m";DIM="\033[2m";BLUE="\033[94m"
def c(t,code): return f"{code}{t}{R}"

# ── top 20 ports ─────────────────────────────────────────
TOP20 = [21,22,23,25,53,80,110,111,135,139,143,443,445,
         993,995,1723,3306,3389,5900,8080]
TOP5  = [22,80,443,445,3389]

PORT_NAMES = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
    110:"POP3",111:"RPC",135:"MSRPC",139:"NetBIOS",143:"IMAP",
    443:"HTTPS",445:"SMB",993:"IMAPS",995:"POP3S",1723:"PPTP",
    3306:"MySQL",3389:"RDP",5900:"VNC",8080:"HTTP-Alt",
}

# ─────────────────────────────────────────────────────────
# OS FINGERPRINT — TTL + TCP Window heuristic
# ─────────────────────────────────────────────────────────
def guess_os(ttl: int, window: int = 0) -> tuple[str, str]:
    """
    Returns (os_guess, confidence).
    TTL is observed at scanner — subtract up to 5 hops tolerance.
    """
    # normalise to nearest starting TTL
    if   ttl >= 250:  base = 255
    elif ttl >= 120:  base = 128
    elif ttl >= 60:   base = 64
    elif ttl >= 30:   base = 32
    else:             base = ttl

    if base == 255:
        return "Cisco / Network Device", "HIGH"
    if base == 128:
        if window in (8192, 65535, 64240):
            return "Windows (10/11/Server)", "HIGH"
        return "Windows", "MED"
    if base == 64:
        # Linux vs macOS vs FreeBSD — use window
        if window == 65535:
            return "macOS / FreeBSD", "MED"
        if window in (5840, 14600, 29200, 14480):
            return "Linux", "HIGH"
        if window == 0 or window == -1:
            return "Linux / macOS", "LOW"
        return "Linux / macOS", "MED"
    if base == 32:
        return "Windows 9x / Old Device", "LOW"
    return "Unknown", "LOW"

OS_COLORS = {
    "Windows": YELLOW,
    "Linux":   GREEN,
    "macOS":   CYAN,
    "Cisco":   MAGENTA,
    "Unknown": DIM,
}
def os_color(guess: str) -> str:
    for k, col in OS_COLORS.items():
        if k.lower() in guess.lower():
            return col
    return DIM

# ─────────────────────────────────────────────────────────
# ARP SCAN — find live hosts on LAN
# ─────────────────────────────────────────────────────────
def arp_scan(subnet: str, timeout: float = 2.0) -> list[dict]:
    """
    Broadcast ARP who-has for every IP in subnet.
    Returns list of {ip, mac} for hosts that reply.
    """
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0

    net    = ipaddress.ip_network(subnet, strict=False)
    # skip network + broadcast address
    hosts  = [str(h) for h in net.hosts()]

    pkt    = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    result, _ = srp(pkt, timeout=timeout, verbose=0)

    found = []
    seen  = set()
    for _, rcv in result:
        ip  = rcv[ARP].psrc
        mac = rcv[ARP].hwsrc
        if ip not in seen:
            seen.add(ip)
            found.append({"ip": ip, "mac": mac})
    return found

# ─────────────────────────────────────────────────────────
# ICMP PING — supplement ARP for routed subnets
# ─────────────────────────────────────────────────────────
def icmp_ping(ip: str, timeout: float = 1.0) -> tuple[bool, int]:
    """
    Send ICMP echo-request via scapy.
    Returns (alive, ttl).
    """
    from scapy.all import IP, ICMP, sr1, conf
    conf.verb = 0
    pkt  = IP(dst=ip) / ICMP()
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp and resp.haslayer(ICMP) and resp[ICMP].type == 0:
        return True, resp[IP].ttl
    return False, 0

# ─────────────────────────────────────────────────────────
# TCP SYN SCAN — one port, returns (open, window)
# ─────────────────────────────────────────────────────────
def syn_probe(ip: str, port: int, timeout: float = 1.0) -> tuple[bool, int]:
    """
    Half-open SYN scan. Returns (open, tcp_window).
    Uses scapy; requires root.
    """
    from scapy.all import IP, TCP, sr1, conf
    conf.verb = 0
    pkt  = IP(dst=ip) / TCP(dport=port, flags="S", window=65535)
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp and resp.haslayer(TCP):
        flags = resp[TCP].flags
        if flags & 0x12 == 0x12:   # SYN-ACK
            win = resp[TCP].window
            # send RST to close cleanly
            from scapy.all import send
            send(IP(dst=ip)/TCP(dport=port,sport=resp[TCP].dport,flags="R"),verbose=0)
            return True, win
    return False, 0

# ─────────────────────────────────────────────────────────
# TCP CONNECT FALLBACK (no root needed)
# ─────────────────────────────────────────────────────────
def tcp_connect(ip: str, port: int, timeout: float = 0.8) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False

# ─────────────────────────────────────────────────────────
# SCAN ONE HOST — ports + OS fingerprint
# ─────────────────────────────────────────────────────────
def scan_host(ip: str, ports: list, delay: float,
              use_syn: bool, timeout: float) -> dict:
    """Full scan of one host. Returns result dict."""
    result = {
        "ip": ip, "mac": "?",
        "ttl": 0, "window": 0,
        "os": "Unknown", "os_conf": "LOW",
        "open_ports": [],
        "scan_time": datetime.datetime.now().isoformat(),
    }

    # ICMP to get TTL
    alive, ttl = icmp_ping(ip, timeout)
    if ttl:
        result["ttl"] = ttl

    # port scan
    max_window = 0
    open_ports = []

    def probe_port(port):
        nonlocal max_window
        time.sleep(delay)
        if use_syn:
            is_open, win = syn_probe(ip, port, timeout)
            if is_open and win > max_window:
                max_window = win
        else:
            is_open = tcp_connect(ip, port, timeout)
            win = 0
        if is_open:
            open_ports.append(port)

    with ThreadPoolExecutor(max_workers=10) as exe:
        list(exe.map(probe_port, ports))

    result["open_ports"] = sorted(open_ports)
    result["window"]     = max_window

    # OS guess
    if result["ttl"]:
        os_g, conf_g = guess_os(result["ttl"], max_window)
        result["os"]      = os_g
        result["os_conf"] = conf_g

    return result

# ─────────────────────────────────────────────────────────
# HOSTNAME RESOLUTION
# ─────────────────────────────────────────────────────────
def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

# ─────────────────────────────────────────────────────────
# TABLE PRINTER
# ─────────────────────────────────────────────────────────
def print_table(results: list, ports: list):
    print()
    print(c("  ── SCAN RESULTS ────────────────────────────────────────────────────────", CYAN))
    print()

    # header
    print(f"  {c('IP ADDRESS',-1):<27}{c('MAC',-1):<21}"
          f"{c('TTL',-1):<6}{c('OS FINGERPRINT',-1):<28}{c('OPEN PORTS',-1)}")
    print("  " + c("─"*95, DIM))

    for r in results:
        ip_s   = c(r["ip"], GREEN+BOLD)
        mac_s  = c(r.get("mac","?"), DIM)
        ttl_s  = c(str(r["ttl"]) if r["ttl"] else "?", YELLOW)
        oc     = os_color(r["os"])
        conf   = r["os_conf"]
        conf_c = GREEN if conf=="HIGH" else YELLOW if conf=="MED" else DIM
        os_s   = c(r["os"], oc) + " " + c(f"[{conf}]", conf_c)

        port_strs = []
        for p in r["open_ports"]:
            name = PORT_NAMES.get(p, "?")
            port_strs.append(c(f"{p}", GREEN) + c(f"/{name}", DIM))
        ports_s = "  ".join(port_strs) if port_strs else c("(none open)", DIM)

        print(f"  {ip_s:<36}{mac_s:<30}{ttl_s:<15}{os_s:<47}  {ports_s}")

        hostname = resolve_hostname(r["ip"])
        if hostname:
            print(f"  {c('  hostname:', DIM)} {c(hostname, CYAN)}")

    print()
    print(c("  ── PORT LEGEND ─────────────────────────────────────────────────────────", DIM))
    for p in ports:
        if p in PORT_NAMES:
            print(f"  {c(str(p), GREEN):<8} {c(PORT_NAMES[p], DIM)}")
    print()

# ─────────────────────────────────────────────────────────
# JSON OUTPUT
# ─────────────────────────────────────────────────────────
def write_json(results: list, path: str, subnet: str):
    out = {
        "scan_time"  : datetime.datetime.now().isoformat(),
        "subnet"     : subnet,
        "host_count" : len(results),
        "hosts"      : results,
    }
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print(c(f"  ✔ JSON saved → {path}", GREEN))

# ─────────────────────────────────────────────────────────
# SIMULATION MODE — inject fake hosts, no root needed
# ─────────────────────────────────────────────────────────
def simulate(output: str | None, fast: bool):
    ports = TOP5 if fast else TOP20

    fake_hosts = [
        {"ip":"192.168.1.1",  "mac":"aa:bb:cc:11:22:01","ttl":64,  "window":14600,
         "os":"Linux",                "os_conf":"HIGH","open_ports":[22,80,443]},
        {"ip":"192.168.1.5",  "mac":"aa:bb:cc:11:22:05","ttl":128, "window":65535,
         "os":"Windows (10/11/Server)","os_conf":"HIGH","open_ports":[135,139,445,3389]},
        {"ip":"192.168.1.10", "mac":"aa:bb:cc:11:22:0a","ttl":64,  "window":65535,
         "os":"macOS / FreeBSD",      "os_conf":"MED", "open_ports":[22,443,5900]},
        {"ip":"192.168.1.20", "mac":"aa:bb:cc:11:22:14","ttl":255, "window":0,
         "os":"Cisco / Network Device","os_conf":"HIGH","open_ports":[22,23,80]},
        {"ip":"192.168.1.50", "mac":"aa:bb:cc:11:22:32","ttl":64,  "window":29200,
         "os":"Linux",                "os_conf":"HIGH","open_ports":[22,80,3306]},
    ]
    for h in fake_hosts:
        h["scan_time"] = datetime.datetime.now().isoformat()

    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   PROJECT #12 · NETWORK SCANNER + OS FINGERPRINTING  ║", CYAN))
    print(c("  ║   [SIMULATION MODE — no root / network needed]        ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════════╝", CYAN))
    print()
    print(f"  Subnet   : {c('192.168.1.0/24', YELLOW)}")
    print(f"  Hosts    : {c(str(len(fake_hosts)), GREEN+BOLD)} live")
    print(f"  Ports    : {c(str(len(ports)), MAGENTA)} ({('fast' if fast else 'full')} mode)")
    print(c("  ⚠  Authorised networks only.", RED))

    print_table(fake_hosts, ports)

    # OS summary
    print(c("  ── OS DISTRIBUTION ─────────────────────────────────────", CYAN))
    from collections import Counter
    dist = Counter(h["os"].split("/")[0].strip() for h in fake_hosts)
    for os_name, count in dist.most_common():
        bar  = "█" * count
        col  = os_color(os_name)
        print(f"  {c(f'{os_name:<28}', col)} {c(bar, col)} {count}")
    print()

    if output:
        write_json(fake_hosts, output, "192.168.1.0/24")

    # verify OS fingerprint logic
    print(c("  ── FINGERPRINT VERIFICATION ────────────────────────────", CYAN))
    tests = [
        (64,  14600, "Linux"),
        (128, 65535, "Windows"),
        (64,  65535, "macOS"),
        (255, 0,     "Cisco"),
        (63,  29200, "Linux"),   # 1 hop from Linux box
        (127, 64240, "Windows"), # 1 hop from Windows
    ]
    all_pass = True
    for ttl, win, expected in tests:
        guess, conf = guess_os(ttl, win)
        ok = expected.lower() in guess.lower()
        all_pass = all_pass and ok
        icon = c("✔", GREEN) if ok else c("✗", RED)
        print(f"  {icon} TTL={ttl:<4} WIN={win:<6} → {c(guess, os_color(guess)):<40} "
              f"{c('['+conf+']', GREEN if conf=='HIGH' else YELLOW)}")
    print()
    print(c("  ✔ ALL FINGERPRINT TESTS PASSED" if all_pass
            else "  ✗ SOME TESTS FAILED", GREEN+BOLD if all_pass else RED))
    print()

# ─────────────────────────────────────────────────────────
# LIVE SCAN
# ─────────────────────────────────────────────────────────
def live_scan(subnet: str, ports: list, delay: float,
              timeout: float, output: str | None, fast: bool):
    use_syn = (os.geteuid() == 0)   # root → SYN scan; else TCP connect

    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   PROJECT #12 · NETWORK SCANNER + OS FINGERPRINTING  ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════════╝", CYAN))
    print()
    print(c("  ⚠  Authorised networks only.", RED))
    print()
    print(f"  Subnet   : {c(subnet, YELLOW)}")
    print(f"  Ports    : {c(str(len(ports)), MAGENTA)} ({'fast' if fast else 'full'} mode)")
    print(f"  Method   : {c('SYN scan (root)', GREEN) if use_syn else c('TCP connect (no-root)', YELLOW)}")
    print(f"  Delay    : {delay}s   Timeout: {timeout}s")

    # ── host discovery ────────────────────────────────────
    print(c(f"\n  ── HOST DISCOVERY ─────────────────────────────────────", CYAN))
    t0 = time.time()
    live = []

    if use_syn:
        print(c("  ARP scan …", DIM), end="", flush=True)
        try:
            arp_hosts = arp_scan(subnet, timeout)
            mac_map   = {h["ip"]: h["mac"] for h in arp_hosts}
        except Exception as e:
            mac_map = {}
            print(c(f" ARP failed: {e}", YELLOW))
    else:
        mac_map = {}

    # ICMP ping sweep for hosts not caught by ARP (routed subnets)
    net   = ipaddress.ip_network(subnet, strict=False)
    hosts = [str(h) for h in net.hosts()]
    print(c(f"  ICMP ping sweep ({len(hosts)} hosts) …", DIM))
    ping_live = set(mac_map.keys())

    def ping_one(ip):
        alive, _ = icmp_ping(ip, timeout)
        if alive:
            ping_live.add(ip)

    with ThreadPoolExecutor(max_workers=50) as exe:
        list(exe.map(ping_one, hosts))

    # combine
    for ip in sorted(ping_live, key=lambda x: [int(p) for p in x.split(".")]):
        live.append({"ip": ip, "mac": mac_map.get(ip, "?")})

    print(c(f"  {len(live)} live host(s) found in {time.time()-t0:.1f}s", GREEN))

    if not live:
        print(c("  No hosts found. Check subnet, interface, or try --simulate.", YELLOW))
        return

    # ── per-host scan ─────────────────────────────────────
    print(c(f"\n  ── PORT SCAN + OS FINGERPRINT ─────────────────────────", CYAN))
    results = []
    for i, h in enumerate(live, 1):
        ip = h["ip"]
        print(f"  Scanning {c(ip, YELLOW)} ({i}/{len(live)}) …", end="\r", flush=True)
        r       = scan_host(ip, ports, delay, use_syn, timeout)
        r["mac"] = h["mac"]
        results.append(r)
        print(f"  {c('✔', GREEN)} {c(ip, YELLOW):<18} "
              f"OS={c(r['os'][:22], os_color(r['os'])):<35} "
              f"ports={c(str(len(r['open_ports'])), CYAN)} open")

    # ── table ─────────────────────────────────────────────
    print_table(results, ports)

    if output:
        write_json(results, output, subnet)

# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Project #12 — Network Scanner + OS Fingerprinting")
    parser.add_argument("--subnet",   default="192.168.1.0/24")
    parser.add_argument("--fast",     action="store_true",   help="Top 5 ports only")
    parser.add_argument("--output",   default=None,          help="Save JSON to file")
    parser.add_argument("--delay",    type=float, default=0.05)
    parser.add_argument("--timeout",  type=float, default=1.0)
    parser.add_argument("--simulate", action="store_true",   help="Demo mode, no network")
    args = parser.parse_args()

    ports = TOP5 if args.fast else TOP20

    if args.simulate:
        simulate(args.output, args.fast)
    else:
        live_scan(args.subnet, ports, args.delay, args.timeout, args.output, args.fast)

if __name__ == "__main__":
    main()