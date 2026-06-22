#!/usr/bin/env python3
"""
============================================================
  PROJECT #13 — WiFi Deauthentication Detector
  100 Ethical Hacking Projects Series
  Role    : DEFENDER — detects deauth attacks, no transmission
  Requires: WiFi adapter with monitor mode support
  Lib     : scapy (802.11 frame parsing)
============================================================

  ╔══════════════════════════════════════════════════════╗
  ║          ⚠  LEGAL NOTICE  ⚠                         ║
  ║  Passive sniffing of 802.11 frames is legal in most  ║
  ║  jurisdictions for your own network. Confirm local   ║
  ║  law. This tool DETECTS ONLY — sends zero packets.   ║
  ╚══════════════════════════════════════════════════════╝

HOW DEAUTH ATTACKS WORK
------------------------
802.11 management frames (type=0) are unauthenticated — any
station can forge them. A deauth frame (subtype=12) or
disassoc frame (subtype=10) forces a client to disconnect.
Attacker floods: aireplay-ng -0 100 -a AP_MAC -c CLIENT_MAC
Client repeatedly disconnects → can't use WiFi.
Used as setup for WPA handshake capture (force reconnect).

DEFENSE AGAINST DEAUTH ATTACKS
---------------------------------
1. 802.11w (PMF — Protected Management Frames)
   WPA3 mandates it; WPA2 supports it as optional.
   PMF cryptographically signs management frames — forged
   deauths are rejected by the AP and client. Enable in
   router settings: "Management Frame Protection = Required".
   Most modern routers (2019+) support this.

2. WIDS (Wireless IDS) — commercial: Cisco AIR, Aruba RFProtect.
   Open-source: this script + Kismet + Wazuh integration.
   Alert triggers IR response: channel-hop to confirm,
   locate attacker via RSSI triangulation.

3. 5 GHz / 6 GHz bands — deauth tools mostly target 2.4 GHz.
   Move critical devices to 5/6 GHz; use band steering.

4. VPN on all WiFi devices — even if deauthed and reconnected
   through attacker MITM, traffic is encrypted end-to-end.

5. ROGUE AP DETECTION — if attacker captures handshake after
   deauth and cracks PSK, rogue AP detection (BSSID whitelist)
   prevents evil-twin association.

MONITOR MODE SETUP (Linux)
----------------------------
  # Method 1: airmon-ng (install: sudo apt install aircrack-ng)
  sudo airmon-ng start wlan0        # creates wlan0mon
  sudo python3 project13_deauth_detector.py --iface wlan0mon

  # Method 2: iw (manual)
  sudo ip link set wlan0 down
  sudo iw dev wlan0 set type monitor
  sudo ip link set wlan0 up
  sudo python3 project13_deauth_detector.py --iface wlan0

  # Restore managed mode (or press Ctrl+C — auto-restore):
  sudo airmon-ng stop wlan0mon
  sudo ip link set wlan0 down
  sudo iw dev wlan0 set type managed
  sudo ip link set wlan0 up

USAGE
------
  sudo python3 project13_deauth_detector.py --iface wlan0mon
  sudo python3 project13_deauth_detector.py --iface wlan0mon --threshold 3 --window 5
  sudo python3 project13_deauth_detector.py --iface wlan0mon --log deauth_log.json
  python3 project13_deauth_detector.py --simulate          # no adapter needed
============================================================
"""

import argparse, sys, os, time, datetime, json, threading
from collections import defaultdict, deque

# ── colours ───────────────────────────────────────────────
R="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
YELLOW="\033[93m";CYAN="\033[96m";MAGENTA="\033[95m";DIM="\033[2m"
BLINK="\033[5m"
def c(t,code): return f"{code}{t}{R}"

# ── 802.11 deauth reason codes ────────────────────────────
REASON_CODES = {
    0:  "Reserved",
    1:  "Unspecified",
    2:  "Prev auth no longer valid",
    3:  "Deauth: station leaving IBSS/ESS",
    4:  "Inactivity — disassociated",
    5:  "AP can't handle all associations",
    6:  "Class 2 frame from non-auth station",
    7:  "Class 3 frame from non-assoc station",
    8:  "Disassoc: station leaving BSS",
    9:  "Station not authenticated",
    10: "Power capability unacceptable",
    11: "Supported channels unacceptable",
    13: "Invalid IE",
    14: "MIC failure",
    15: "4-Way Handshake timeout",
    16: "Group Key Handshake timeout",
    17: "IE in 4-Way Handshake differs",
    18: "Invalid group cipher",
    19: "Invalid pairwise cipher",
    20: "Invalid AKMP",
    21: "Unsupported RSN IE version",
    22: "Invalid RSN IE capabilities",
    23: "IEEE 802.1X auth failed",
    24: "Cipher rejected per policy",
}

def reason_str(code: int) -> str:
    return REASON_CODES.get(code, f"Unknown ({code})")

# ─────────────────────────────────────────────────────────
# MONITOR MODE MANAGEMENT
# ─────────────────────────────────────────────────────────
original_iface = None
monitor_iface  = None

def enable_monitor(iface: str) -> str | None:
    """
    Try airmon-ng first, then iw fallback.
    Returns monitor interface name or None on failure.
    """
    global original_iface, monitor_iface
    original_iface = iface

    # try airmon-ng
    ret = os.system(f"sudo airmon-ng start {iface} 2>/dev/null")
    mon = iface + "mon"
    if os.path.exists(f"/sys/class/net/{mon}"):
        monitor_iface = mon
        print(c(f"  ✔ Monitor mode enabled via airmon-ng → {mon}", GREEN))
        return mon

    # try iw
    cmds = [
        f"sudo ip link set {iface} down",
        f"sudo iw dev {iface} set type monitor",
        f"sudo ip link set {iface} up",
    ]
    for cmd in cmds:
        os.system(f"{cmd} 2>/dev/null")

    if _iface_exists(iface):
        monitor_iface = iface
        print(c(f"  ✔ Monitor mode enabled via iw → {iface}", GREEN))
        return iface

    return None

def disable_monitor():
    """Restore managed mode — called on exit."""
    global original_iface, monitor_iface
    if not monitor_iface:
        return
    print(c(f"\n  Restoring managed mode on {original_iface} …", YELLOW))

    # try airmon-ng stop
    os.system(f"sudo airmon-ng stop {monitor_iface} 2>/dev/null")

    # iw fallback
    cmds = [
        f"sudo ip link set {original_iface} down",
        f"sudo iw dev {original_iface} set type managed",
        f"sudo ip link set {original_iface} up",
    ]
    for cmd in cmds:
        os.system(f"{cmd} 2>/dev/null")

    print(c(f"  ✔ Interface {original_iface} restored to managed mode.", GREEN))

def _iface_exists(iface: str) -> bool:
    return os.path.exists(f"/sys/class/net/{iface}")

# ─────────────────────────────────────────────────────────
# ATTACK TRACKER — sliding window per source MAC
# ─────────────────────────────────────────────────────────
class AttackTracker:
    def __init__(self, threshold: int, window: float):
        self.threshold = threshold
        self.window    = window
        # {src_mac → deque of timestamps}
        self.history: dict[str, deque] = defaultdict(deque)
        self.alerted: set = set()     # MACs already alerted this burst
        self.lock = threading.Lock()

    def record(self, src: str, dst: str, reason: int,
               ts: float) -> bool:
        """
        Record one deauth packet. Returns True if attack threshold reached.
        """
        with self.lock:
            dq = self.history[src]
            dq.append(ts)
            # evict old entries outside window
            while dq and dq[0] < ts - self.window:
                dq.popleft()
            count = len(dq)
            is_attack = count >= self.threshold

            # reset alert flag if burst subsided
            if not is_attack and src in self.alerted:
                self.alerted.discard(src)

            new_alert = is_attack and src not in self.alerted
            if new_alert:
                self.alerted.add(src)

            return new_alert, count

    def all_sources(self) -> dict:
        with self.lock:
            return {mac: len(dq) for mac, dq in self.history.items() if dq}

# ─────────────────────────────────────────────────────────
# STATS
# ─────────────────────────────────────────────────────────
stats = {
    "total_deauth": 0,
    "total_disassoc": 0,
    "alerts": 0,
    "sources": defaultdict(int),
    "targets": defaultdict(int),
}
stats_lock = threading.Lock()
event_log  = []   # for --log output

# ─────────────────────────────────────────────────────────
# PACKET HANDLER
# ─────────────────────────────────────────────────────────
def make_handler(tracker: AttackTracker, verbose: bool):
    from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas

    def handler(pkt):
        # 802.11 type=0 (management), subtype=12 (deauth) or 10 (disassoc)
        if not pkt.haslayer(Dot11):
            return

        dot11 = pkt[Dot11]
        ftype    = dot11.type
        fsubtype = dot11.subtype
        ts       = time.time()
        ts_str   = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

        is_deauth   = (ftype == 0 and fsubtype == 12)
        is_disassoc = (ftype == 0 and fsubtype == 10)

        if not (is_deauth or is_disassoc):
            return

        src    = dot11.addr2 or "??:??:??:??:??:??"
        dst    = dot11.addr1 or "ff:ff:ff:ff:ff:ff"
        bssid  = dot11.addr3 or "??:??:??:??:??:??"

        reason = 0
        if is_deauth and pkt.haslayer(Dot11Deauth):
            reason = pkt[Dot11Deauth].reason
        elif is_disassoc and pkt.haslayer(Dot11Disas):
            reason = pkt[Dot11Disas].reason

        frame_type = "DEAUTH" if is_deauth else "DISASSOC"

        with stats_lock:
            if is_deauth:
                stats["total_deauth"] += 1
            else:
                stats["total_disassoc"] += 1
            stats["sources"][src] += 1
            stats["targets"][dst] += 1

        # log event
        event = {
            "time": ts_str, "type": frame_type,
            "src": src, "dst": dst, "bssid": bssid,
            "reason": reason, "reason_str": reason_str(reason),
        }
        event_log.append(event)

        # normal packet log
        ft_col = RED if is_deauth else YELLOW
        if verbose:
            print(f"  {c(ts_str, DIM)}  {c(frame_type, ft_col):<20}"
                  f"  src={c(src, MAGENTA)}  dst={c(dst, CYAN)}"
                  f"  reason={c(str(reason), YELLOW)} "
                  f"{c('('+reason_str(reason)+')', DIM)}")

        # attack detection
        new_alert, count = tracker.record(src, dst, reason, ts)
        if new_alert:
            with stats_lock:
                stats["alerts"] += 1
            alert_num = stats["alerts"]
            print()
            print(c(f"  ╔══════════════════════════════════════════════════════╗", RED))
            print(c(f"  ║  ⚠  DEAUTH ATTACK DETECTED  #{alert_num:<3}                  ║", RED+BOLD))
            print(c(f"  ╚══════════════════════════════════════════════════════╝", RED))
            print(f"  {c('Time      :', DIM)} {c(ts_str, CYAN)}")
            print(f"  {c('Source MAC:', DIM)} {c(src, RED+BOLD)}  ← attacker / forged")
            print(f"  {c('Target MAC:', DIM)} {c(dst, YELLOW)}")
            print(f"  {c('BSSID     :', DIM)} {c(bssid, MAGENTA)}")
            print(f"  {c('Count     :', DIM)} {c(str(count), RED+BOLD)} frames in "
                  f"{tracker.window}s window "
                  f"(threshold={tracker.threshold})")
            print(f"  {c('Reason    :', DIM)} {reason} — {reason_str(reason)}")
            print(c("  ─────────────────────────────────────────────────────────", DIM))
            print(c("  Possible attack: WPA handshake capture / DoS disconnect", YELLOW))
            print(c("  Defense: Enable 802.11w (PMF) on AP and clients.", GREEN))
            print()

    return handler

# ─────────────────────────────────────────────────────────
# LIVE SNIFF
# ─────────────────────────────────────────────────────────
def live_sniff(iface: str, threshold: int, window: float,
               log_path: str | None, verbose: bool, auto_monitor: bool):
    from scapy.all import sniff, conf
    conf.verb = 0

    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   PROJECT #13 · WiFi DEAUTH DETECTOR                 ║", CYAN))
    print(c("  ║   Passive monitor — sends zero packets                ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════════╝", CYAN))
    print()
    print(c("  ⚠  Monitor your own network only.", RED))

    mon_iface = iface
    if auto_monitor:
        print(c(f"\n  Enabling monitor mode on {iface} …", CYAN))
        result = enable_monitor(iface)
        if result:
            mon_iface = result
        else:
            print(c(f"  [!] Could not enable monitor mode automatically.", YELLOW))
            print(c(f"  Run manually: sudo airmon-ng start {iface}", DIM))
            print(c(f"  Then: sudo python3 {__file__} --iface {iface}mon\n", DIM))
            sys.exit(1)

    print()
    print(f"  Interface : {c(mon_iface, YELLOW)}")
    print(f"  Threshold : {c(str(threshold), RED)} deauths in {c(str(window)+'s', RED)} → ALERT")
    print(f"  Verbose   : {verbose}")
    print(c("\n  Sniffing 802.11 management frames … (Ctrl+C to stop)\n", GREEN))
    print(f"  {'TIME':13}  {'TYPE':12}  {'SOURCE':20}  {'TARGET':20}  REASON")
    print("  " + c("─"*80, DIM))

    tracker = AttackTracker(threshold, window)
    handler = make_handler(tracker, verbose)

    try:
        sniff(iface=mon_iface, prn=handler, store=False,
              filter="")   # BPF can't filter 802.11 frames reliably — filter in handler
    except PermissionError:
        print(c("\n  [ERROR] Need root. Run with sudo.", RED))
        sys.exit(1)
    except OSError as e:
        print(c(f"\n  [ERROR] Interface error: {e}", RED))
        print(c(f"  Is {mon_iface} in monitor mode? Try --auto-monitor", YELLOW))
        sys.exit(1)
    except KeyboardInterrupt:
        pass

    _print_summary(tracker, log_path)
    if auto_monitor:
        disable_monitor()

# ─────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────
def _print_summary(tracker, log_path):
    print(c(f"\n  ── SESSION SUMMARY ─────────────────────────────────────", CYAN))
    print(f"  Deauth frames    : {c(str(stats['total_deauth']), RED)}")
    print(f"  Disassoc frames  : {c(str(stats['total_disassoc']), YELLOW)}")
    print(f"  Attack alerts    : {c(str(stats['alerts']), RED+BOLD)}")

    if stats["sources"]:
        print(c("\n  Top sources:", DIM))
        for mac, n in sorted(stats["sources"].items(), key=lambda x: -x[1])[:5]:
            bar = "█" * min(n, 20)
            print(f"  {c(mac, MAGENTA)}  {c(bar, RED)}  {n}")

    if log_path:
        with open(log_path, "w") as f:
            json.dump({
                "session": datetime.datetime.now().isoformat(),
                "stats"  : {k: v for k, v in stats.items()
                            if not isinstance(v, defaultdict)},
                "events" : event_log,
            }, f, indent=2)
        print(c(f"\n  ✔ Log saved → {log_path}", GREEN))
    print()

# ─────────────────────────────────────────────────────────
# SIMULATION MODE
# ─────────────────────────────────────────────────────────
def simulate(threshold: int, window: float, log_path: str | None):
    """
    Replay a crafted sequence of deauth events through the
    tracker logic — proves detection without a real adapter.
    """
    from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas, RadioTap
    from scapy.packet import Packet

    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   PROJECT #13 · WiFi DEAUTH DETECTOR                 ║", CYAN))
    print(c("  ║   [SIMULATION MODE — no adapter needed]               ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════════╝", CYAN))
    print()
    print(f"  Threshold : {c(str(threshold), RED)} deauths / {c(str(window)+'s', RED)}")
    print()

    tracker = AttackTracker(threshold, window)

    # sequence: legit traffic then burst attack
    AP_MAC      = "aa:bb:cc:11:22:33"
    CLIENT_A    = "11:22:33:aa:bb:cc"
    CLIENT_B    = "44:55:66:dd:ee:ff"
    ATTACKER    = "de:ad:be:ef:ca:fe"

    sequence = [
        # (src,  dst,       bssid,   reason, frame_type, sleep, label)
        (AP_MAC,   CLIENT_A, AP_MAC,  3, "DEAUTH",   0.1, "Legit: AP deauths client A (leaving ESS)"),
        (CLIENT_B, AP_MAC,   AP_MAC,  8, "DISASSOC", 0.1, "Legit: Client B disassociates"),
        (AP_MAC,   CLIENT_A, AP_MAC,  1, "DEAUTH",   0.1, "Legit: periodic AP-initiated deauth"),
        # ── ATTACK BEGINS ─────────────────────────────────────
        (ATTACKER, CLIENT_A, AP_MAC,  7, "DEAUTH",   0.05, "⚠ ATTACK: forged deauth #1"),
        (ATTACKER, CLIENT_A, AP_MAC,  7, "DEAUTH",   0.05, "⚠ ATTACK: forged deauth #2"),
        (ATTACKER, CLIENT_A, AP_MAC,  7, "DEAUTH",   0.05, "⚠ ATTACK: forged deauth #3"),
        (ATTACKER, CLIENT_A, AP_MAC,  7, "DEAUTH",   0.05, "⚠ ATTACK: forged deauth #4"),
        (ATTACKER, CLIENT_A, AP_MAC,  7, "DEAUTH",   0.05, "⚠ ATTACK: forged deauth #5 (THRESHOLD!)"),
        (ATTACKER, CLIENT_B, AP_MAC,  7, "DEAUTH",   0.05, "⚠ ATTACK: same attacker, new target"),
        (ATTACKER, "ff:ff:ff:ff:ff:ff", AP_MAC, 7, "DEAUTH", 0.05, "⚠ ATTACK: broadcast deauth"),
    ]

    verbose_handler = make_handler(tracker, verbose=True)

    print(f"  {'TIME':13}  {'TYPE':12}  {'SOURCE':20}  {'TARGET':20}  REASON")
    print("  " + c("─"*85, DIM))

    for src, dst, bssid, reason, ftype, sleep, label in sequence:
        time.sleep(sleep)
        ts_str = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(c(f"\n  [{label}]", DIM if "Legit" in label else YELLOW))

        # build a minimal scapy Dot11 packet the handler can parse
        if ftype == "DEAUTH":
            pkt = (Dot11(type=0, subtype=12, addr1=dst, addr2=src, addr3=bssid)
                   / Dot11Deauth(reason=reason))
        else:
            pkt = (Dot11(type=0, subtype=10, addr1=dst, addr2=src, addr3=bssid)
                   / Dot11Disas(reason=reason))

        verbose_handler(pkt)

    _print_summary(tracker, log_path)

    # assertions
    print(c("  ── TEST ASSERTIONS ─────────────────────────────────────", CYAN))
    attack_detected   = stats["alerts"] >= 1
    correct_attacker  = ATTACKER in stats["sources"]
    total_ok          = stats["total_deauth"] >= 8
    print(f"  {'✔' if attack_detected  else '✗'} Attack detected (alerts={stats['alerts']})")
    print(f"  {'✔' if correct_attacker else '✗'} Attacker MAC tracked ({ATTACKER})")
    print(f"  {'✔' if total_ok         else '✗'} Frame counter (deauth={stats['total_deauth']})")
    all_pass = attack_detected and correct_attacker and total_ok
    print()
    print(c("  ✔ ALL ASSERTIONS PASSED" if all_pass
            else "  ✗ SOME FAILED", GREEN+BOLD if all_pass else RED))
    print()

# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Project #13 — WiFi Deauth Detector")
    parser.add_argument("--iface",        default="wlan0mon",
                        help="Monitor mode interface (default: wlan0mon)")
    parser.add_argument("--threshold",    type=int, default=5,
                        help="Deauth count threshold for alert (default: 5)")
    parser.add_argument("--window",       type=float, default=10.0,
                        help="Sliding window in seconds (default: 10)")
    parser.add_argument("--log",          default=None,
                        help="Save event log to JSON file")
    parser.add_argument("--verbose",      action="store_true",
                        help="Print every deauth packet (default: alerts only)")
    parser.add_argument("--auto-monitor", action="store_true",
                        help="Auto-enable monitor mode via airmon-ng/iw")
    parser.add_argument("--simulate",     action="store_true",
                        help="Run without real adapter")
    args = parser.parse_args()

    if args.simulate:
        simulate(args.threshold, args.window, args.log)
    else:
        live_sniff(args.iface, args.threshold, args.window,
                   args.log, args.verbose, args.auto_monitor)

if __name__ == "__main__":
    main()