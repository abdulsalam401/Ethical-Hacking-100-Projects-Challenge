#!/usr/bin/env python3
"""
PROJECT #38 — Auto-Recon — Automated Reconnaissance Framework
"""

import os
import sys
import re
import time
import socket
import threading
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("[-] dnspython not installed. Run: pip install dnspython")

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[-] requests not installed. Run: pip install requests")

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("[-] python-whois not installed. Run: pip install python-whois")

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    print("[-] beautifulsoup4 not installed. Run: pip install beautifulsoup4")

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; MAGENTA=''; WHITE=''
        LIGHTBLACK_EX=''; LIGHTRED_EX=''; LIGHTGREEN_EX=''; LIGHTYELLOW_EX=''
        LIGHTBLUE_EX=''; LIGHTMAGENTA_EX=''; LIGHTCYAN_EX=''
    class Style:
        BRIGHT=''; DIM=''; RESET_ALL=''

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
    RED = Fore.RED + Style.BRIGHT
    YELLOW = Fore.YELLOW + Style.BRIGHT
    GREEN = Fore.GREEN + Style.BRIGHT
    BLUE = Fore.BLUE + Style.BRIGHT
    CYAN = Fore.CYAN + Style.BRIGHT

# Subdomain wordlist
SUBDOMAIN_WORDLIST = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
    'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
    'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
    'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
    'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
    'web', 'media', 'email', 'images', 'img', 'download', 'dns', 'piwik', 'stats',
    'dashboard', 'portal', 'manage', 'start', 'info', 'apps', 'video', 'sip',
    'dns2', 'api', 'cdn', 'mssql', 'remote', 'server', 'ftp2', 'stage', 'monitor',
    'tracking', 'host', 'server2', 'gw', 'proxy', 'vps', 'cloud', 'files',
    'backup', 'git', 'svn', 'jenkins', 'jira', 'confluence', 'bitbucket', 'staging',
    'assets', 'res', 'app', 'auth', 'login', 'signup', 'register', 'account',
    'my', 'partner', 'partners', 'clients', 'client', 'billing', 'pay', 'payment',
    'gateway', 'api2', 'api3', 'ws', 'soap', 'rest', 'graphql', 'elastic',
    'kibana', 'logstash', 'grafana', 'prometheus', 'alertmanager', 'thanos',
]

# Top 100 ports
TOP_PORTS = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC',
    139: 'NETBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS',
    995: 'POP3S', 1723: 'PPTP', 3306: 'MYSQL', 3389: 'RDP', 5432: 'POSTGRESQL',
    5900: 'VNC', 6379: 'REDIS', 8080: 'HTTP-ALT', 8443: 'HTTPS-ALT', 27017: 'MONGODB',
}

# Technology detection patterns
TECH_PATTERNS = {
    'nginx': r'nginx',
    'apache': r'Apache',
    'iis': r'Microsoft-IIS',
    'tomcat': r'Apache-Coyote|Tomcat',
    'nodejs': r'Node.js',
    'express': r'Express',
    'django': r'Django',
    'flask': r'Flask',
    'rails': r'Rails|Ruby on Rails',
    'php': r'PHP',
    'wordpress': r'wp-content|wp-includes|WordPress',
    'joomla': r'Joomla',
    'drupal': r'Drupal',
    'magento': r'Magento',
    'shopify': r'Shopify',
    'woocommerce': r'woocommerce',
    'bootstrap': r'bootstrap',
    'jquery': r'jquery',
    'react': r'react',
    'vue': r'vue',
    'angular': r'angular',
    'laravel': r'Laravel',
}

class AutoRecon:
    def __init__(self, domain, threads=10, rate_limit=10, output_file="recon_report.html", quick=False):
        self.domain = domain
        self.threads = threads
        self.rate_limit = rate_limit
        self.output_file = output_file
        self.quick = quick
        self.results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'dns_records': {},
            'subdomains': [],
            'whois': {},
            'open_ports': [],
            'services': [],
            'technologies': [],
        }
        self.lock = threading.Lock()
        self.request_count = 0
        self.session = None
        
    def banner(self):
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}  PROJECT #38 — Auto-Recon Framework{Colors.ENDC}")
        print(f"{Colors.OKBLUE}  Automated domain reconnaissance and OSINT{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        print(f"{Colors.RED}⚠️⚠️⚠️  ETHICAL WARNING  ⚠️⚠️⚠️{Colors.ENDC}")
        print(f"{Colors.YELLOW}Only scan domains you own or have permission to test.{Colors.ENDC}\n")
        
        print(f"{Colors.OKGREEN}[+] Target: {self.domain}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Threads: {self.threads}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Quick mode: {self.quick}{Colors.ENDC}\n")
    
    def rate_limit_wait(self):
        if self.rate_limit > 0:
            time.sleep(1.0 / self.rate_limit)
    
    def setup_session(self):
        if not REQUESTS_AVAILABLE:
            return None
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        return session
    
    def dns_lookup(self, record_type):
        if not DNS_AVAILABLE:
            return []
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            answers = resolver.resolve(self.domain, record_type)
            return [str(rdata) for rdata in answers]
        except:
            return []
    
    def enumerate_dns(self):
        print(f"{Colors.OKBLUE}[*] Enumerating DNS records...{Colors.ENDC}")
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        for record_type in record_types:
            records = self.dns_lookup(record_type)
            if records:
                self.results['dns_records'][record_type] = records
                print(f"{Colors.OKGREEN}[+] {record_type}: {', '.join(records[:3])}{Colors.ENDC}")
            else:
                print(f"{Colors.DIM}[*] {record_type}: No records found{Colors.ENDC}")
    
    def check_subdomain(self, subdomain):
        full_domain = f"{subdomain}.{self.domain}"
        self.rate_limit_wait()
        try:
            socket.gethostbyname(full_domain)
            return full_domain
        except:
            return None
    
    def discover_subdomains(self):
        print(f"\n{Colors.OKBLUE}[*] Discovering subdomains...{Colors.ENDC}")
        found = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_subdomain, sub): sub for sub in SUBDOMAIN_WORDLIST}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    print(f"{Colors.OKGREEN}[+] Found: {result}{Colors.ENDC}")
        self.results['subdomains'] = found
        print(f"{Colors.OKGREEN}[+] Found {len(found)} subdomains{Colors.ENDC}")
    
    def whois_lookup(self):
        print(f"\n{Colors.OKBLUE}[*] Performing WHOIS lookup...{Colors.ENDC}")
        if not WHOIS_AVAILABLE:
            print(f"{Colors.WARNING}[!] python-whois not installed{Colors.ENDC}")
            return
        try:
            w = whois.whois(self.domain)
            self.results['whois'] = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
            }
            print(f"{Colors.OKGREEN}[+] Registrar: {w.registrar}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] Creation: {w.creation_date}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.WARNING}[!] WHOIS lookup failed: {e}{Colors.ENDC}")
    
    def scan_port(self, ip, port):
        self.rate_limit_wait()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                service = TOP_PORTS.get(port, 'unknown')
                return {'port': port, 'service': service, 'status': 'open'}
            return None
        except:
            return None
    
    def port_scan(self, ip=None):
        print(f"\n{Colors.OKBLUE}[*] Scanning ports...{Colors.ENDC}")
        if not ip:
            try:
                ip = socket.gethostbyname(self.domain)
            except:
                print(f"{Colors.FAIL}[-] Could not resolve domain{Colors.ENDC}")
                return
        
        print(f"{Colors.OKGREEN}[+] Scanning IP: {ip}{Colors.ENDC}")
        ports_to_scan = list(TOP_PORTS.keys())[:100]
        if self.quick:
            ports_to_scan = ports_to_scan[:20]
            print(f"{Colors.DIM}[*] Quick mode: top 20 ports{Colors.ENDC}")
        
        open_ports = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, ip, port): port for port in ports_to_scan}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    print(f"{Colors.OKGREEN}[+] Port {result['port']}: {result['service']} (OPEN){Colors.ENDC}")
        
        self.results['open_ports'] = open_ports
        print(f"{Colors.OKGREEN}[+] Found {len(open_ports)} open ports{Colors.ENDC}")
        
        for port_info in open_ports:
            if port_info['port'] in [80, 443, 8080, 8443]:
                self.detect_service(ip, port_info['port'])
    
    def detect_service(self, ip, port):
        protocol = 'https' if port in [443, 8443] else 'http'
        url = f"{protocol}://{ip}:{port}"
        try:
            self.rate_limit_wait()
            response = self.session.get(url, timeout=5, verify=False)
            server = response.headers.get('Server', '')
            techs = self.detect_technologies(response.text)
            
            service_info = {
                'port': port,
                'url': url,
                'server': server,
                'status_code': response.status_code,
                'technologies': techs,
            }
            with self.lock:
                self.results['services'].append(service_info)
                for tech in techs:
                    if tech not in self.results['technologies']:
                        self.results['technologies'].append(tech)
            
            print(f"{Colors.OKGREEN}[+] Service on port {port}: {server or 'Unknown'}{Colors.ENDC}")
            if techs:
                print(f"{Colors.DIM}[+] Technologies: {', '.join(techs)}{Colors.ENDC}")
        except:
            pass
    
    def detect_technologies(self, html):
        detected = []
        content = html.lower()
        for tech, pattern in TECH_PATTERNS.items():
            if re.search(pattern, content, re.IGNORECASE):
                detected.append(tech)
        return detected
    
    def run(self):
        self.banner()
        
        if not DNS_AVAILABLE:
            print(f"{Colors.FAIL}[-] dnspython not available{Colors.ENDC}")
            return
        
        self.session = self.setup_session()
        self.enumerate_dns()
        self.whois_lookup()
        self.discover_subdomains()
        
        try:
            ip = socket.gethostbyname(self.domain)
            self.port_scan(ip)
        except Exception as e:
            print(f"{Colors.FAIL}[-] Port scan failed: {e}{Colors.ENDC}")
        
        self.generate_report()
    
    def generate_report(self):
        print(f"\n{Colors.OKBLUE}[*] Generating HTML report...{Colors.ENDC}")
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Auto-Recon Report</title>
    <style>
        body {{font-family:'Segoe UI',sans-serif;background:#1a1a2e;color:#e0e0e0;padding:20px;}}
        .container {{max-width:1200px;margin:0 auto;}}
        .header {{background:linear-gradient(135deg,#16213e,#0f3460);padding:30px;border-radius:10px;}}
        .header h1 {{color:#00d4ff;}}
        .header .warning {{color:#ff4444;font-weight:bold;}}
        .section {{background:#2d2d44;padding:20px;border-radius:10px;margin:15px 0;}}
        .section h2 {{color:#00d4ff;border-bottom:1px solid #3d3d5a;padding-bottom:10px;}}
        .stat-box {{display:inline-block;background:#1a1a3e;padding:15px;border-radius:8px;margin:5px;min-width:150px;}}
        .stat-box .value {{font-size:24px;font-weight:bold;color:#00d4ff;}}
        .stat-box .label {{color:#888;font-size:12px;}}
        table {{width:100%;border-collapse:collapse;margin:10px 0;}}
        th, td {{padding:10px;text-align:left;border-bottom:1px solid #3d3d5a;}}
        th {{color:#00d4ff;}}
        .dns-record {{background:#1a1a3e;padding:5px;margin:2px 0;border-radius:4px;font-family:monospace;font-size:12px;}}
        .port-open {{color:#00ff88;font-weight:bold;}}
        .defense {{background:#0f3460;padding:15px;border-radius:8px;margin-top:20px;}}
        .defense h3 {{color:#00d4ff;}}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🔍 Auto-Recon Report</h1>
        <p class="warning">⚠️ EDUCATIONAL USE ONLY ⚠️</p>
        <p>Domain: {self.domain}</p>
        <p>Scan Time: {self.results['timestamp']}</p>
    </div>
    
    <div class="section">
        <h2>📊 Summary</h2>
        <div>
            <div class="stat-box"><div class="value">{len(self.results['dns_records'])}</div><div class="label">DNS Records</div></div>
            <div class="stat-box"><div class="value">{len(self.results['subdomains'])}</div><div class="label">Subdomains</div></div>
            <div class="stat-box"><div class="value">{len(self.results['open_ports'])}</div><div class="label">Open Ports</div></div>
            <div class="stat-box"><div class="value">{len(self.results['technologies'])}</div><div class="label">Technologies</div></div>
        </div>
    </div>
    
    <div class="section">
        <h2>🌐 DNS Records</h2>"""
        
        for record_type, records in self.results['dns_records'].items():
            html += f'<p><strong>{record_type}:</strong></p>'
            for record in records[:5]:
                html += f'<div class="dns-record">{record}</div>'
        
        html += """
    </div>
    
    <div class="section">
        <h2>📋 Subdomains</h2>"""
        
        if self.results['subdomains']:
            for sub in self.results['subdomains'][:20]:
                html += f'<div style="padding:5px;background:#1a1a3e;margin:2px 0;border-radius:4px;">🔗 {sub}</div>'
        else:
            html += '<p style="color:#888;">No subdomains found</p>'
        
        html += """
    </div>
    
    <div class="section">
        <h2>📡 Open Ports</h2>
        <table>
            <tr><th>Port</th><th>Service</th><th>Status</th></tr>"""
        
        for port in self.results['open_ports']:
            html += f"""
            <tr>
                <td>{port['port']}</td>
                <td>{port['service']}</td>
                <td class="port-open">OPEN</td>
            </tr>"""
        
        html += """
        </table>
    </div>
    
    <div class="section">
        <h2>🛠️ Services</h2>"""
        
        for service in self.results['services']:
            html += f"""
        <div style="background:#1a1a3e;padding:10px;margin:5px 0;border-radius:4px;">
            <strong>Port {service['port']}</strong> - {service['url']}
            <br><span style="color:#888;">Server: {service.get('server', 'Unknown')}</span>
            <br><span style="color:#888;">Technologies: {', '.join(service.get('technologies', []))}</span>
        </div>"""
        
        html += """
    </div>
    
    <div class="section">
        <h2>📝 WHOIS</h2>"""
        
        if self.results['whois']:
            for key, value in self.results['whois'].items():
                if value:
                    html += f'<p><strong>{key}:</strong> {value}</p>'
        else:
            html += '<p style="color:#888;">WHOIS data not available</p>'
        
        html += """
    </div>
    
    <div class="section defense">
        <h3>🛡️ Defenses Against Reconnaissance</h3>
        <table>
            <tr><th>Defense</th><th>Description</th></tr>
            <tr><td>Rate Limiting</td><td>Limit requests per IP</td></tr>
            <tr><td>Firewall Rules</td><td>Block suspicious traffic</td></tr>
            <tr><td>DNS Response Filtering</td><td>Filter DNS queries</td></tr>
            <tr><td>WHOIS Privacy</td><td>Hide domain owner information</td></tr>
            <tr><td>Honeypot Services</td><td>Detect and trap scanners</td></tr>
            <tr><td>IDS/IPS</td><td>Detect reconnaissance patterns</td></tr>
        </table>
    </div>
    
    <div style="text-align:center;color:#666;margin-top:30px;">
        <p>Generated by Auto-Recon | 100 Ethical Hacking Projects</p>
        <p>⚠️ For Educational Purposes Only ⚠️</p>
    </div>
</div>
</body>
</html>"""
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"{Colors.OKGREEN}[+] Report saved to {self.output_file}{Colors.ENDC}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Auto-Recon Framework")
    parser.add_argument("--domain", required=True, help="Target domain")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("--rate-limit", type=int, default=10, help="Requests per second")
    parser.add_argument("--output", default="recon_report.html", help="HTML report file")
    parser.add_argument("--quick", action="store_true", help="Quick scan (top 20 ports)")
    
    args = parser.parse_args()
    
    recon = AutoRecon(
        domain=args.domain,
        threads=args.threads,
        rate_limit=args.rate_limit,
        output_file=args.output,
        quick=args.quick
    )
    
    recon.run()

if __name__ == "__main__":
    main()