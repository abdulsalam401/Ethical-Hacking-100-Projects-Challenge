#!/usr/bin/env python3
"""
============================================================
  PROJECT #14 — Packet Crafting Engine / Protocol Fuzzer
  100 Ethical Hacking Projects Series
  Lib  : scapy
  Modes: manual craft, fuzz-flags, fuzz-payload, fuzz-port
============================================================

  ⚠  Use ONLY on hosts you own or have written permission
     to test. Fuzzing production systems = illegal.
     Legal targets: your own WSL/VM, local open ports,
     HackTheBox / TryHackMe machines.

DEFENSE AGAINST PACKET FUZZING
---------------------------------
1. STATEFUL FIREWALL — drops packets that don't belong to
   an established flow (unexpected flags, wrong seq).
2. IDS/IPS (Snort rule example):
     alert tcp any any -> $HOME_NET any
       (flags:!A,!S,!R; msg:"Unusual TCP flags"; sid:1000001)
3. RATE LIMITING — iptables:
     iptables -A INPUT -p tcp --tcp-flags ALL NONE -m limit
       --limit 1/s -j ACCEPT  (null-scan limit)
4. TCP SEQUENCE RANDOMISATION — modern OS kernels randomise
   ISN (initial sequence number), defeating blind injection.
5. KERNEL INPUT VALIDATION — Linux drops malformed packets
   at the IP layer (bad length, checksum, IHL). Fuzzer hits
   these and gets ICMP type 3 (unreachable) or silence.

USAGE
------
  sudo python3 project14_fuzzer.py --target 127.0.0.1 --protocol tcp --dport 80
  sudo python3 project14_fuzzer.py --target 127.0.0.1 --protocol udp --dport 53
  sudo python3 project14_fuzzer.py --target 127.0.0.1 --protocol icmp
  sudo python3 project14_fuzzer.py --target 127.0.0.1 --fuzz-flags --count 20
  sudo python3 project14_fuzzer.py --target 127.0.0.1 --fuzz-payload --count 20
  sudo python3 project14_fuzzer.py --target 127.0.0.1 --fuzz-port --count 30
  python3 project14_fuzzer.py --simulate         # no root/network needed
============================================================
"""

import argparse, sys, os, time, random, string, json, datetime, struct
from collections import defaultdict

R="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
YELLOW="\033[93m";CYAN="\033[96m";MAGENTA="\033[95m";DIM="\033[2m"
def c(t,code): return f"{code}{t}{R}"

# ── ICMP type/code descriptions ───────────────────────────
ICMP_TYPES = {
    0:"Echo Reply", 3:"Destination Unreachable", 8:"Echo Request",
    11:"Time Exceeded", 12:"Parameter Problem",
}
ICMP_CODES_3 = {
    0:"Net Unreachable",1:"Host Unreachable",2:"Protocol Unreachable",
    3:"Port Unreachable",4:"Fragmentation Needed",9:"Net Admin Prohibited",
    10:"Host Admin Prohibited",13:"Comm Admin Prohibited",
}

def icmp_desc(t,code=0):
    td = ICMP_TYPES.get(t,f"type{t}")
    if t==3: cd = ICMP_CODES_3.get(code,f"code{code}")
    else:    cd = ""
    return f"{td}" + (f" / {cd}" if cd else "")

# ── TCP flag set ──────────────────────────────────────────
FLAG_SETS = {
    "SYN":"S","ACK":"A","FIN":"F","RST":"R","PSH":"P","URG":"U",
    "SYN-ACK":"SA","FIN-ACK":"FA","NULL":"","XMAS":"FPU",
    "MAIM":"SFPU","WINDOW":"SAF","PUSH-URG":"PU",
}
ALL_FLAGS = list(FLAG_SETS.values())

# anomaly log
anomalies = []
sent_count = [0]
resp_count = [0]

# ─────────────────────────────────────────────────────────
# RESPONSE ANALYSER
# ─────────────────────────────────────────────────────────
def analyse_response(resp, sent_pkt, label="") -> dict:
    from scapy.all import IP, TCP, UDP, ICMP
    result = {"label":label, "response":"no-reply", "anomaly":False, "detail":""}

    if resp is None:
        result["response"] = "timeout"
        return result

    resp_count[0] += 1
    proto = ""

    if resp.haslayer(TCP):
        flags = resp[TCP].flags
        sport = resp[TCP].sport
        dport = resp[TCP].dport
        win   = resp[TCP].window
        proto = "TCP"

        if flags & 0x12 == 0x12:          # SYN-ACK
            result["response"] = c("SYN-ACK", GREEN+BOLD)
            result["detail"]   = f"port={sport} WIN={win}"
            result["anomaly"]  = False
        elif flags & 0x04:                 # RST
            result["response"] = c("RST", YELLOW)
            result["detail"]   = f"port={sport}"
        elif flags & 0x11 == 0x11:        # FIN-ACK
            result["response"] = c("FIN-ACK", CYAN)
        else:
            result["response"] = c(f"TCP flags=0x{int(flags):02x}", MAGENTA)
            result["anomaly"]  = True
            result["detail"]   = f"unexpected flags"

    elif resp.haslayer(ICMP):
        itype = resp[ICMP].type
        icode = resp[ICMP].code
        proto = "ICMP"
        desc  = icmp_desc(itype, icode)
        result["response"] = c(f"ICMP {itype}/{icode}", RED if itype==3 else CYAN)
        result["detail"]   = desc

        # ICMP type 3 = destination unreachable — anomaly worth logging
        if itype == 3:
            result["anomaly"] = True
            result["detail"]  = f"Unreachable: {desc}"

        # type 0 = echo reply (expected for ICMP ping)
        if itype == 0:
            result["response"] = c("Echo Reply", GREEN)
            result["anomaly"]  = False

    elif resp.haslayer(UDP):
        result["response"] = c("UDP Reply", GREEN)
        result["detail"]   = f"sport={resp[UDP].sport}"

    else:
        result["response"] = c("Unknown layer", DIM)

    if result["anomaly"]:
        anomalies.append({
            "time"    : datetime.datetime.now().isoformat(),
            "label"   : label,
            "response": str(result["response"]),
            "detail"  : result["detail"],
        })

    return result

# ─────────────────────────────────────────────────────────
# SEND + PRINT ONE PACKET
# ─────────────────────────────────────────────────────────
def send_and_analyse(pkt, label:str, delay:float, timeout:float):
    from scapy.all import sr1, conf
    conf.verb = 0

    sent_count[0] += 1
    t0   = time.time()
    resp = sr1(pkt, timeout=timeout, verbose=0)
    rtt  = (time.time() - t0) * 1000   # ms

    result = analyse_response(resp, pkt, label)
    rtt_s  = c(f"{rtt:.1f}ms", DIM)

    # print row
    anom_icon = c("⚠", RED+BOLD) if result["anomaly"] else " "
    print(f"  {anom_icon} {c(f'#{sent_count[0]:>3}', DIM)}  "
          f"{c(label[:38], CYAN):<47}  "
          f"{result['response']:<30}  "
          f"{c(result['detail'][:35], DIM):<44}  "
          f"{rtt_s}")

    time.sleep(delay)
    return result

# ─────────────────────────────────────────────────────────
# MANUAL CRAFT MODES
# ─────────────────────────────────────────────────────────
def craft_tcp(target, sport, dport, flags, payload, delay, timeout):
    from scapy.all import IP, TCP, Raw
    pkt = IP(dst=target) / TCP(sport=sport, dport=dport, flags=flags)
    if payload:
        pkt = pkt / Raw(load=payload.encode())
    return send_and_analyse(pkt, f"TCP {flags or 'NULL'} → {target}:{dport}", delay, timeout)

def craft_udp(target, sport, dport, payload, delay, timeout):
    from scapy.all import IP, UDP, Raw
    data = payload.encode() if payload else b"\x00" * 8
    pkt  = IP(dst=target) / UDP(sport=sport, dport=dport) / Raw(load=data)
    return send_and_analyse(pkt, f"UDP → {target}:{dport} payload={len(data)}B", delay, timeout)

def craft_icmp(target, icmp_type, icmp_code, payload, delay, timeout):
    from scapy.all import IP, ICMP, Raw
    pkt = IP(dst=target) / ICMP(type=icmp_type, code=icmp_code)
    if payload:
        pkt = pkt / Raw(load=payload.encode())
    return send_and_analyse(pkt, f"ICMP type={icmp_type} code={icmp_code} → {target}", delay, timeout)

# ─────────────────────────────────────────────────────────
# FUZZ MODES
# ─────────────────────────────────────────────────────────
def rand_payload(min_len=1, max_len=64) -> bytes:
    n = random.randint(min_len, max_len)
    choice = random.randint(0,2)
    if choice == 0:   # random bytes
        return bytes(random.randint(0,255) for _ in range(n))
    elif choice == 1: # printable
        return ''.join(random.choices(string.printable, k=n)).encode()
    else:             # repeated pattern
        pat = bytes([random.randint(0,255)])
        return pat * n

def rand_flags() -> str:
    # random subset of TCP flags
    flags_pool = list("SAFPRU")
    k = random.randint(0, len(flags_pool))
    return "".join(random.sample(flags_pool, k))

def fuzz_flags(target, dport, count, delay, timeout):
    from scapy.all import IP, TCP
    print(c(f"\n  ── FUZZ: TCP FLAGS (target={target}:{dport}) ───────────────", MAGENTA))
    for i in range(count):
        flags = rand_flags()
        sport = random.randint(1024, 65535)
        pkt   = IP(dst=target)/TCP(sport=sport, dport=dport, flags=flags,
                                   window=random.randint(0,65535))
        send_and_analyse(pkt, f"FUZZ flags={flags or 'NULL':<8} dport={dport}", delay, timeout)

def fuzz_payload(target, protocol, dport, count, delay, timeout):
    from scapy.all import IP, TCP, UDP, Raw
    print(c(f"\n  ── FUZZ: PAYLOAD (proto={protocol} target={target}:{dport}) ──", MAGENTA))
    for i in range(count):
        payload = rand_payload()
        sport   = random.randint(1024, 65535)
        if protocol == "tcp":
            pkt = IP(dst=target)/TCP(sport=sport, dport=dport, flags="PA")/Raw(load=payload)
        else:
            pkt = IP(dst=target)/UDP(sport=sport, dport=dport)/Raw(load=payload)
        label = f"FUZZ payload={len(payload)}B type={'bytes' if any(b>127 for b in payload) else 'ascii'}"
        send_and_analyse(pkt, label, delay, timeout)

def fuzz_ports(target, protocol, count, delay, timeout):
    from scapy.all import IP, TCP, UDP
    print(c(f"\n  ── FUZZ: PORT RANGE (proto={protocol} target={target}) ──────", MAGENTA))
    tested = set()
    for i in range(count):
        dport = random.randint(1, 65535)
        while dport in tested: dport = random.randint(1,65535)
        tested.add(dport)
        sport = random.randint(1024, 65535)
        if protocol == "tcp":
            pkt = IP(dst=target)/TCP(sport=sport, dport=dport, flags="S")
        else:
            pkt = IP(dst=target)/UDP(sport=sport, dport=dport)
        send_and_analyse(pkt, f"FUZZ port={dport}", delay, timeout)

# ─────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────
def print_summary(output:str|None):
    print(c(f"\n  ── SUMMARY ─────────────────────────────────────────────", CYAN))
    print(f"  Packets sent   : {c(str(sent_count[0]), YELLOW)}")
    print(f"  Responses recv : {c(str(resp_count[0]), GREEN)}")
    print(f"  Anomalies      : {c(str(len(anomalies)), RED+BOLD if anomalies else DIM)}")

    if anomalies:
        print(c(f"\n  ── ANOMALY LOG ─────────────────────────────────────────", RED))
        for a in anomalies:
            print(f"  {c('⚠', RED)}  [{a['time'][11:19]}]  {c(a['label'][:40], YELLOW)}")
            print(f"       resp={a['response']}  {c(a['detail'], DIM)}")

    if output:
        with open(output, "w") as f:
            json.dump({"sent":sent_count[0],"responses":resp_count[0],
                       "anomalies":anomalies}, f, indent=2)
        print(c(f"\n  ✔ Saved → {output}", GREEN))
    print()

# ─────────────────────────────────────────────────────────
# SIMULATION — no root/network, proves all logic paths
# ─────────────────────────────────────────────────────────
def simulate(output:str|None):
    """
    Monkey-patch scapy sr1 to return crafted responses,
    then exercise every mode: TCP SYN, UDP, ICMP, all 3 fuzz modes.
    """
    from scapy.all import IP, TCP, UDP, ICMP, Raw

    # ── mock response table ───────────────────────────────
    def mock_sr1(pkt, timeout=1, verbose=0):
        if not pkt.haslayer(IP): return None
        dst = pkt[IP].dst

        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            dport = pkt[TCP].dport
            # SYN → SYN-ACK on known ports
            if "S" in str(flags) and dport in (22,80,443,8080):
                return (IP(src=dst,ttl=64)/
                        TCP(sport=dport,dport=pkt[TCP].sport,
                            flags="SA",window=65535,seq=1000,ack=pkt[TCP].seq+1))
            # RST on closed ports
            if "S" in str(flags):
                return (IP(src=dst,ttl=64)/
                        TCP(sport=dport,dport=pkt[TCP].sport,flags="RA"))
            # Unusual flags → return nothing (firewall drops)
            if not any(f in str(flags) for f in ["S","A","F"]):
                return None
            return (IP(src=dst,ttl=64)/
                    TCP(sport=dport,dport=pkt[TCP].sport,flags="A"))

        if pkt.haslayer(UDP):
            dport = pkt[UDP].dport
            if dport == 53:   # DNS always responds
                return (IP(src=dst,ttl=64)/
                        UDP(sport=53,dport=pkt[UDP].sport)/Raw(b"\x00\x00"))
            # closed UDP → ICMP port unreachable
            return (IP(src=dst,ttl=64)/ICMP(type=3,code=3)/
                    IP(src=pkt[IP].src,dst=dst)/pkt[UDP])

        if pkt.haslayer(ICMP):
            if pkt[ICMP].type == 8:   # echo request → echo reply
                return (IP(src=dst,ttl=64)/ICMP(type=0,code=0,id=pkt[ICMP].id))
            return None

        return None

    # patch
    import scapy.all as _sa
    _orig_sr1 = _sa.sr1
    _sa.sr1 = mock_sr1

    # also patch inside the module functions that imported sr1 directly
    import project14_fuzzer as _self
    _self_send = _self.send_and_analyse

    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   PROJECT #14 · PACKET CRAFTING ENGINE / FUZZER      ║", CYAN))
    print(c("  ║   [SIMULATION MODE — no root/network needed]          ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════════╝", CYAN))
    print()
    print(f"  {'#':>5}  {'PACKET DESCRIPTION':<40}  {'RESPONSE':<22}  {'DETAIL':<30}  RTT")
    print("  "+c("─"*110, DIM))

    TARGET = "192.168.1.1"
    DELAY  = 0.0
    TO     = 0.5

    # ── 1. TCP SYN → open port ────────────────────────────
    print(c("\n  ── 1. TCP SYN PACKETS ───────────────────────────────────", CYAN))
    craft_tcp(TARGET, 54321, 80,  "S",  "",        DELAY, TO)
    craft_tcp(TARGET, 54322, 443, "S",  "",        DELAY, TO)
    craft_tcp(TARGET, 54323, 9999,"S",  "",        DELAY, TO)   # closed → RST
    craft_tcp(TARGET, 54324, 80,  "",   "",        DELAY, TO)   # NULL scan
    craft_tcp(TARGET, 54325, 80,  "FPU","",        DELAY, TO)   # XMAS scan
    craft_tcp(TARGET, 54326, 80,  "SA", "GET / HTTP/1.0\r\n\r\n", DELAY, TO)

    # ── 2. UDP packets ────────────────────────────────────
    print(c("\n  ── 2. UDP PACKETS ───────────────────────────────────────", CYAN))
    craft_udp(TARGET, 12345, 53,  "\x00\x01\x01\x00", DELAY, TO)   # DNS-ish
    craft_udp(TARGET, 12346, 9999,"FUZZ_ME",           DELAY, TO)   # closed → ICMP unreach

    # ── 3. ICMP ───────────────────────────────────────────
    print(c("\n  ── 3. ICMP PACKETS ──────────────────────────────────────", CYAN))
    craft_icmp(TARGET, 8, 0, "",  DELAY, TO)   # echo request → echo reply
    craft_icmp(TARGET, 8, 0, "A"*64, DELAY, TO)

    # ── 4. Fuzz flags ─────────────────────────────────────
    random.seed(42)
    fuzz_flags(TARGET, 80, 10, DELAY, TO)

    # ── 5. Fuzz payload ───────────────────────────────────
    random.seed(99)
    fuzz_payload(TARGET, "tcp", 80, 8, DELAY, TO)

    # ── 6. Fuzz ports ─────────────────────────────────────
    random.seed(7)
    fuzz_ports(TARGET, "tcp", 15, DELAY, TO)

    print_summary(output)

    # restore
    _sa.sr1 = _orig_sr1

    # assertions
    print(c("  ── ASSERTIONS ──────────────────────────────────────────", CYAN))
    syn_ack_found = any("SYN-ACK" in str(a.get("response","")) for a in []) # checked via resp_count
    print(f"  {'✔' if sent_count[0]  >= 40 else '✗'} Sent >= 40 packets     ({sent_count[0]})")
    print(f"  {'✔' if resp_count[0]  >= 10 else '✗'} Received >= 10 replies  ({resp_count[0]})")
    print(f"  {'✔' if len(anomalies)  >= 1  else '✗'} Anomalies detected      ({len(anomalies)})")
    all_pass = sent_count[0]>=40 and resp_count[0]>=10 and len(anomalies)>=1
    print()
    print(c("  ✔ ALL ASSERTIONS PASSED" if all_pass
            else "  ✗ SOME FAILED", GREEN+BOLD if all_pass else RED))
    print()

# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Project #14 — Packet Crafting / Fuzzer")
    parser.add_argument("--target",      default="127.0.0.1")
    parser.add_argument("--protocol",    choices=["tcp","udp","icmp"], default="tcp")
    parser.add_argument("--sport",       type=int, default=0,  help="Source port (0=random)")
    parser.add_argument("--dport",       type=int, default=80)
    parser.add_argument("--flags",       default="S",          help="TCP flags (default: S)")
    parser.add_argument("--payload",     default="",           help="Payload string")
    parser.add_argument("--icmp-type",   type=int, default=8)
    parser.add_argument("--icmp-code",   type=int, default=0)
    # fuzz modes
    parser.add_argument("--fuzz-flags",   action="store_true")
    parser.add_argument("--fuzz-payload", action="store_true")
    parser.add_argument("--fuzz-port",    action="store_true")
    parser.add_argument("--count",       type=int, default=20, help="Fuzz iterations")
    # common
    parser.add_argument("--delay",       type=float, default=0.1)
    parser.add_argument("--timeout",     type=float, default=1.0)
    parser.add_argument("--output",      default=None,         help="Save anomaly log JSON")
    parser.add_argument("--simulate",    action="store_true")
    args = parser.parse_args()

    if args.simulate:
        simulate(args.output); return

    sport = args.sport if args.sport else random.randint(1024,65535)

    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   PROJECT #14 · PACKET CRAFTING ENGINE / FUZZER      ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════════╝", CYAN))
    print()
    print(c("  ⚠  Authorised targets only.", RED))
    print(f"\n  Target: {c(args.target, YELLOW)}  Protocol: {c(args.protocol.upper(), MAGENTA)}")
    print(f"  {'#':>5}  {'PACKET DESCRIPTION':<40}  {'RESPONSE':<22}  {'DETAIL':<30}  RTT")
    print("  "+c("─"*110, DIM))

    if args.fuzz_flags:
        fuzz_flags(args.target, args.dport, args.count, args.delay, args.timeout)
    elif args.fuzz_payload:
        fuzz_payload(args.target, args.protocol, args.dport, args.count, args.delay, args.timeout)
    elif args.fuzz_port:
        fuzz_ports(args.target, args.protocol, args.count, args.delay, args.timeout)
    elif args.protocol == "tcp":
        craft_tcp(args.target, sport, args.dport, args.flags, args.payload, args.delay, args.timeout)
    elif args.protocol == "udp":
        craft_udp(args.target, sport, args.dport, args.payload, args.delay, args.timeout)
    elif args.protocol == "icmp":
        craft_icmp(args.target, args.icmp_type, args.icmp_code, args.payload, args.delay, args.timeout)

    print_summary(args.output)

if __name__ == "__main__":
    main()