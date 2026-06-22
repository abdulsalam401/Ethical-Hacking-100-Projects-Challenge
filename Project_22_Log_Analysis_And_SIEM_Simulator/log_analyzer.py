#!/usr/bin/env python3
"""
==============================================================
  PROJECT #22 — Log Analysis & SIEM Simulator (ELK-style)
  Complete version with SQLi, Brute Force, and configurable rules
==============================================================
"""

import re
import json
import argparse
import sys
from datetime import datetime
from collections import defaultdict
from colorama import init, Fore, Style

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

# Default rules (fallback if no rules.json)
DEFAULT_RULES = {
    "sql_injection": {
        "pattern": "('.*OR.*'.*='|;.*--|UNION.*SELECT|' OR '1'='1|' OR 1=1|SELECT.*FROM|INSERT.*INTO|DELETE.*FROM|DROP.*TABLE|1=1;|' OR 1=1 --)",
        "severity": "HIGH",
        "description": "SQL Injection attempt detected"
    },
    "path_traversal": {
        "pattern": "\\.\\./\\.\\./|/etc/passwd|/etc/shadow|/proc/self/environ|C:\\\\Windows\\\\System32|%2e%2e%2f|%2e%2e/",
        "severity": "HIGH",
        "description": "Path traversal attempt detected"
    },
    "xss": {
        "pattern": "<script>|alert\\(|onerror=|javascript:|document\\.cookie|onload=|onmouseover=|onclick=|<iframe|onerror",
        "severity": "MEDIUM",
        "description": "Cross-Site Scripting (XSS) attempt"
    },
    "command_injection": {
        "pattern": ";\\s*(ls|whoami|cat|echo|nc|bash|sh|curl|wget|id|uname|pwd|netstat|dir|type|del|rm|mkdir|ping)|&&\\s*(ls|whoami|cat|echo|nc)|\\|\\s*(ls|whoami|cat|echo)",
        "severity": "HIGH",
        "description": "Command injection attempt"
    },
    "brute_force": {
        "pattern": "Failed password|Authentication failure|Login failed|401|403|Invalid password|Access denied",
        "severity": "MEDIUM",
        "description": "Possible brute force login attempt - check threshold"
    },
    "suspicious_user_agent": {
        "pattern": "curl|wget|python-requests|perl|ruby|nmap|masscan|sqlmap|nikto|dirb|gobuster|Burp|ZAP|Nessus|Hydra|Medusa|John|aircrack|metasploit",
        "severity": "MEDIUM",
        "description": "Suspicious user agent (scanning tool)"
    },
    "directory_bruteforce": {
        "pattern": "\\.php|\\.asp|\\.jsp|\\.do|/admin|/config|/backup|/wp-admin|/wp-login|/phpmyadmin|/cpanel|/webmail|/manager|/sqlmanager|/mysql|/db|/database",
        "severity": "LOW",
        "description": "Potential directory brute force"
    }
}

class LogAnalyzer:
    def __init__(self, log_file, log_type='apache', rules_file=None):
        self.log_file = log_file
        self.log_type = log_type
        self.rules = self.load_rules(rules_file)
        self.alerts = []
        self.log_entries = []
        self.failed_login_timestamps = defaultdict(list)
        self.brute_force_alerts = set()  # Track already alerted IPs
        
    def load_rules(self, rules_file):
        """Load rules from JSON or use defaults"""
        if rules_file:
            try:
                with open(rules_file, 'r') as f:
                    rules = json.load(f)
                print(f"{Colors.OKGREEN}[+] Loaded rules from {rules_file}{Colors.ENDC}")
                return rules
            except Exception as e:
                print(f"{Colors.WARNING}[!] Failed to load rules: {e}{Colors.ENDC}")
                print(f"{Colors.DIM}[*] Using default rules{Colors.ENDC}")
        
        return DEFAULT_RULES
    
    def parse_apache_log(self, line):
        """Parse Apache access log line"""
        pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<time>.*?)\] "(?P<method>.*?) (?P<url>.*?) (?P<protocol>.*?)" (?P<status>\d+) (?P<size>\d+) "(?P<referer>.*?)" "(?P<user_agent>.*?)"'
        
        match = re.match(pattern, line)
        if match:
            data = match.groupdict()
            try:
                data['time'] = datetime.strptime(data['time'], '%d/%b/%Y:%H:%M:%S %z')
            except:
                data['time'] = datetime.now()
            return data
        return None
    
    def parse_log_file(self):
        """Parse log file"""
        print(f"{Colors.OKBLUE}[*] Parsing {self.log_file} ({self.log_type})...{Colors.ENDC}")
        
        entries = []
        try:
            with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
                for line in lines:
                    parsed = None
                    if self.log_type == 'apache':
                        parsed = self.parse_apache_log(line)
                    
                    if parsed:
                        entries.append(parsed)
                        
        except FileNotFoundError:
            print(f"{Colors.FAIL}[-] Log file not found: {self.log_file}{Colors.ENDC}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.FAIL}[-] Error parsing log: {e}{Colors.ENDC}")
            sys.exit(1)
        
        print(f"{Colors.OKGREEN}[+] Parsed {len(entries)} log entries{Colors.ENDC}")
        return entries
    
    def detect_attacks(self, entries):
        """Detect attacks in log entries"""
        print(f"{Colors.OKBLUE}[*] Analyzing for attacks...{Colors.ENDC}")
        
        for entry in entries:
            ip = entry.get('ip', 'Unknown')
            url = entry.get('url', '')
            status = entry.get('status', '')
            user_agent = entry.get('user_agent', '')
            message = entry.get('message', '')
            
            # Check each rule
            for rule_name, rule in self.rules.items():
                pattern = rule['pattern']
                severity = rule['severity']
                description = rule['description']
                
                # Special handling for brute force (threshold-based)
                if rule_name == 'brute_force':
                    if re.search(pattern, str(status) + ' ' + str(message), re.IGNORECASE):
                        self.check_brute_force(ip, entry)
                    continue
                
                # Check if pattern matches URL or message
                if re.search(pattern, str(url) + ' ' + str(message), re.IGNORECASE):
                    alert = {
                        'type': rule_name,
                        'severity': severity,
                        'description': description,
                        'ip': ip,
                        'timestamp': entry.get('time', datetime.now()).isoformat()
                    }
                    
                    # Add details based on alert type
                    if 'url' in entry:
                        alert['url'] = url[:100]
                    if 'user_agent' in entry:
                        alert['user_agent'] = user_agent[:50]
                    
                    self.alerts.append(alert)
        
        print(f"{Colors.OKGREEN}[+] Found {len(self.alerts)} alerts{Colors.ENDC}")
    
    def check_brute_force(self, ip, entry):
        """Check for brute force (more than 5 failures in 10 seconds)"""
        current_time = entry.get('time', datetime.now())
        self.failed_login_timestamps[ip].append(current_time)
        
        # Keep only last 10 seconds
        self.failed_login_timestamps[ip] = [
            t for t in self.failed_login_timestamps[ip] 
            if (current_time - t).total_seconds() <= 10
        ]
        
        # Check if more than 5 failures in 10 seconds
        if len(self.failed_login_timestamps[ip]) > 5 and ip not in self.brute_force_alerts:
            self.brute_force_alerts.add(ip)
            alert = {
                'type': 'brute_force',
                'severity': 'MEDIUM',
                'description': f'Brute force attempt: {len(self.failed_login_timestamps[ip])} failures in 10 seconds',
                'ip': ip,
                'timestamp': current_time.isoformat(),
                'count': len(self.failed_login_timestamps[ip])
            }
            self.alerts.append(alert)
    
    def display_alerts(self):
        """Display alerts in color-coded table"""
        if not self.alerts:
            print(f"\n{Colors.OKGREEN}{'='*80}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[✓] No attacks detected!{Colors.ENDC}")
            print(f"{Colors.OKGREEN}{'='*80}{Colors.ENDC}")
            return
        
        print(f"\n{Colors.FAIL}{'='*120}{Colors.ENDC}")
        print(f"{Colors.FAIL}⚠️⚠️⚠️  ATTACKS DETECTED!  ⚠️⚠️⚠️{Colors.ENDC}")
        print(f"{Colors.FAIL}{'='*120}{Colors.ENDC}")
        
        # Group by severity
        high = [a for a in self.alerts if a['severity'] == 'HIGH']
        medium = [a for a in self.alerts if a['severity'] == 'MEDIUM']
        low = [a for a in self.alerts if a['severity'] == 'LOW']
        
        # Display HIGH severity first
        if high:
            print(f"\n{Colors.FAIL}[!] HIGH SEVERITY:{Colors.ENDC}")
            self.print_alert_table(high)
        
        if medium:
            print(f"\n{Colors.WARNING}[!] MEDIUM SEVERITY:{Colors.ENDC}")
            self.print_alert_table(medium)
        
        if low:
            print(f"\n{Colors.DIM}[!] LOW SEVERITY:{Colors.ENDC}")
            self.print_alert_table(low)
        
        print(f"\n{Colors.FAIL}{'='*120}{Colors.ENDC}")
        print(f"{Colors.FAIL}Total: {len(self.alerts)} alerts (High: {len(high)}, Medium: {len(medium)}, Low: {len(low)}){Colors.ENDC}")
    
    def print_alert_table(self, alerts):
        """Print alerts in table format"""
        print(f"{Colors.HEADER}{'Timestamp':<22} {'IP':<18} {'Type':<18} {'Description':<42} {'Details':<25}{Colors.ENDC}")
        print(f"{Colors.DIM}{'-'*120}{Colors.ENDC}")
        
        for alert in alerts:
            ts = alert.get('timestamp', 'N/A')[:19] if alert.get('timestamp') else 'N/A'
            ip = alert.get('ip', 'Unknown')[:17]
            atype = alert['type'][:17]
            desc = alert['description'][:41]
            details = ''
            
            if 'url' in alert:
                details = alert['url'][:24]
            elif 'user_agent' in alert:
                details = alert['user_agent'][:24]
            elif 'count' in alert:
                details = f"Count: {alert['count']}"
            
            # Color based on severity
            if alert['severity'] == 'HIGH':
                color = Colors.FAIL
            elif alert['severity'] == 'MEDIUM':
                color = Colors.WARNING
            else:
                color = Colors.DIM
            
            print(f"{color}{ts:<22} {ip:<18} {atype:<18} {desc:<42} {details:<25}{Colors.ENDC}")
    
    def print_statistics(self):
        """Print detection statistics"""
        if not self.alerts:
            return
        
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}  DETECTION STATISTICS{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        
        # Count by type
        type_counts = defaultdict(int)
        ip_counts = defaultdict(int)
        
        for alert in self.alerts:
            type_counts[alert['type']] += 1
            ip_counts[alert.get('ip', 'Unknown')] += 1
        
        print(f"\n{Colors.OKGREEN}Attack Types:{Colors.ENDC}")
        for atype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {Colors.DIM}{atype}:{Colors.ENDC} {count}")
        
        print(f"\n{Colors.OKGREEN}Top Attacker IPs:{Colors.ENDC}")
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {Colors.FAIL}{ip}:{Colors.ENDC} {count} alerts")
        
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
    
    def export_json(self, output_file):
        """Export alerts to JSON"""
        if not output_file:
            return
        
        try:
            with open(output_file, 'w') as f:
                json.dump({
                    'scan_info': {
                        'timestamp': datetime.now().isoformat(),
                        'log_file': self.log_file,
                        'log_type': self.log_type,
                        'total_alerts': len(self.alerts),
                        'rules_used': list(self.rules.keys())
                    },
                    'alerts': self.alerts
                }, f, indent=2)
            print(f"\n{Colors.OKGREEN}[+] Alerts exported to {output_file}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] Failed to export: {e}{Colors.ENDC}")
    
    def run(self):
        """Main execution"""
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}  PROJECT #22 — Log Analysis & SIEM Simulator{Colors.ENDC}")
        print(f"{Colors.OKBLUE}  ELK-style log analysis and attack detection{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        # Parse logs
        entries = self.parse_log_file()
        if not entries:
            print(f"{Colors.WARNING}[!] No entries parsed{Colors.ENDC}")
            return
        
        # Detect attacks
        self.detect_attacks(entries)
        
        # Display results
        self.display_alerts()
        self.print_statistics()
        
        return self.alerts

def main():
    parser = argparse.ArgumentParser(description="Log Analysis & SIEM Simulator")
    parser.add_argument("--file", required=True, help="Log file to analyze")
    parser.add_argument("--type", choices=['apache', 'syslog'], default='apache', 
                        help="Log file type")
    parser.add_argument("--rules", help="JSON rules file")
    parser.add_argument("--output", help="Export alerts to JSON")
    
    args = parser.parse_args()
    
    analyzer = LogAnalyzer(args.file, args.type, args.rules)
    alerts = analyzer.run()
    
    if alerts and args.output:
        analyzer.export_json(args.output)

if __name__ == "__main__":
    main()





# #!/usr/bin/env python3
# """
# ==============================================================
#   PROJECT #22 — Log Analysis & SIEM Simulator (ELK-style)
#   Parses logs, detects attacks, generates alerts
# ==============================================================

# FEATURES:
# - Parse Apache access logs, Windows Event Logs, Syslog
# - Detect SQL injection, path traversal, brute force
# - Configurable rules via JSON
# - Color-coded alert table
# - JSON output for SIEM integration

# USAGE:
# --------
#   # Analyze Apache logs
#   python log_analyzer.py --file access.log --type apache
  
#   # Analyze Windows Event Log
#   python log_analyzer.py --file security.evtx --type evtx
  
#   # Analyze Syslog
#   python log_analyzer.py --file syslog --type syslog
  
#   # With custom rules
#   python log_analyzer.py --file access.log --rules rules.json
  
#   # Output JSON
#   python log_analyzer.py --file access.log --output alerts.json
# ==============================================================
# """

# import re
# import json
# import argparse
# import sys
# from datetime import datetime
# from collections import defaultdict
# from colorama import init, Fore, Style

# # Initialize colorama
# init(autoreset=True)

# # Colors
# class Colors:
#     HEADER = Fore.CYAN + Style.BRIGHT
#     OKBLUE = Fore.BLUE + Style.BRIGHT
#     OKGREEN = Fore.GREEN + Style.BRIGHT
#     WARNING = Fore.YELLOW + Style.BRIGHT
#     FAIL = Fore.RED + Style.BRIGHT
#     ENDC = Style.RESET_ALL
#     BOLD = Style.BRIGHT
#     DIM = Fore.LIGHTBLACK_EX
#     MAGENTA = Fore.MAGENTA + Style.BRIGHT

# # Try importing optional libraries
# try:
#     import pandas as pd
#     PANDAS_AVAILABLE = True
# except ImportError:
#     PANDAS_AVAILABLE = False
#     print(f"{Colors.WARNING}[!] pandas not installed. Run: pip install pandas{Colors.ENDC}")

# try:
#     import Evtx
#     EVTX_AVAILABLE = True
# except ImportError:
#     EVTX_AVAILABLE = False

# # Default rules
# DEFAULT_RULES = {
#     "sql_injection": {
#         "pattern": r"('.*OR.*'.*='|;.*--|UNION.*SELECT|' OR '1'='1|' OR 1=1|SELECT.*FROM|INSERT.*INTO|DELETE.*FROM|DROP.*TABLE)",
#         "severity": "HIGH",
#         "description": "SQL Injection attempt detected"
#     },
#     "path_traversal": {
#         "pattern": r"\.\./\.\./|/etc/passwd|/etc/shadow|/proc/self/environ|C:\\Windows\\System32",
#         "severity": "HIGH",
#         "description": "Path traversal attempt detected"
#     },
#     "xss": {
#         "pattern": r"<script>|alert\(|onerror=|javascript:|document\.cookie|onload=|onmouseover=",
#         "severity": "MEDIUM",
#         "description": "Cross-Site Scripting (XSS) attempt"
#     },
#     "command_injection": {
#         "pattern": r";\s*(ls|whoami|cat|echo|nc|bash|sh|curl|wget|id|uname|pwd|netstat)|&&\s*(ls|whoami|cat|echo|nc)",
#         "severity": "HIGH",
#         "description": "Command injection attempt"
#     },
#     "brute_force": {
#         "pattern": r"Failed password|Authentication failure|Login failed|401",
#         "severity": "MEDIUM",
#         "description": "Possible brute force login attempt"
#     },
#     "suspicious_user_agent": {
#         "pattern": r"curl|wget|python|perl|ruby|nmap|masscan|sqlmap|nikto|dirb|gobuster|Burp|ZAP|Nessus",
#         "severity": "MEDIUM",
#         "description": "Suspicious user agent (scanning tool)"
#     },
#     "directory_bruteforce": {
#         "pattern": r"\.php|\.asp|\.jsp|\.do|/admin|/config|/backup|/wp-admin|/wp-login|/phpmyadmin|/cpanel|/webmail",
#         "severity": "LOW",
#         "description": "Potential directory brute force"
#     }
# }

# class LogAnalyzer:
#     def __init__(self, log_file, log_type='apache', rules_file=None):
#         self.log_file = log_file
#         self.log_type = log_type
#         self.rules = self.load_rules(rules_file)
#         self.alerts = []
#         self.log_entries = []
#         self.failed_login_count = defaultdict(int)
#         self.failed_login_timestamps = defaultdict(list)
        
#     def load_rules(self, rules_file):
#         """Load rules from JSON or use defaults"""
#         if rules_file:
#             try:
#                 with open(rules_file, 'r') as f:
#                     rules = json.load(f)
#                 print(f"{Colors.OKGREEN}[+] Loaded rules from {rules_file}{Colors.ENDC}")
#                 return rules
#             except Exception as e:
#                 print(f"{Colors.WARNING}[!] Failed to load rules: {e}{Colors.ENDC}")
#                 print(f"{Colors.DIM}[*] Using default rules{Colors.ENDC}")
        
#         return DEFAULT_RULES
    
#     def parse_apache_log(self, line):
#         """Parse Apache access log line"""
#         # Common Log Format
#         pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<time>.*?)\] "(?P<method>.*?) (?P<url>.*?) (?P<protocol>.*?)" (?P<status>\d+) (?P<size>\d+) "(?P<referer>.*?)" "(?P<user_agent>.*?)"'
        
#         match = re.match(pattern, line)
#         if match:
#             data = match.groupdict()
#             try:
#                 data['time'] = datetime.strptime(data['time'], '%d/%b/%Y:%H:%M:%S %z')
#             except:
#                 data['time'] = datetime.now()
#             return data
#         return None
    
#     def parse_syslog(self, line):
#         """Parse Syslog line"""
#         pattern = r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<service>\S+): (?P<message>.*)'
        
#         match = re.match(pattern, line)
#         if match:
#             data = match.groupdict()
#             try:
#                 data['timestamp'] = datetime.strptime(data['timestamp'], '%b %d %H:%M:%S')
#                 data['timestamp'] = data['timestamp'].replace(year=datetime.now().year)
#             except:
#                 data['timestamp'] = datetime.now()
#             return data
#         return None
    
#     def parse_evtx(self):
#         """Parse Windows Event Log (evtx)"""
#         if not EVTX_AVAILABLE:
#             print(f"{Colors.FAIL}[-] evtx module not installed. Run: pip install evtx{Colors.ENDC}")
#             return []
        
#         entries = []
#         try:
#             import Evtx.Evtx as evtx
#             import Evtx.Views as views
            
#             with evtx.Evtx(self.log_file) as log:
#                 for record in log.records():
#                     try:
#                         data = record.xml()
#                         entries.append({
#                             'xml': data,
#                             'time': datetime.now()
#                         })
#                     except:
#                         continue
#         except Exception as e:
#             print(f"{Colors.FAIL}[-] Failed to parse EVTX: {e}{Colors.ENDC}")
        
#         return entries
    
#     def parse_log_file(self):
#         """Parse log file based on type"""
#         print(f"{Colors.OKBLUE}[*] Parsing {self.log_file} ({self.log_type})...{Colors.ENDC}")
        
#         entries = []
#         try:
#             with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
#                 lines = f.readlines()
                
#                 for line in lines:
#                     parsed = None
#                     if self.log_type == 'apache':
#                         parsed = self.parse_apache_log(line)
#                     elif self.log_type == 'syslog':
#                         parsed = self.parse_syslog(line)
                    
#                     if parsed:
#                         entries.append(parsed)
                        
#         except FileNotFoundError:
#             print(f"{Colors.FAIL}[-] Log file not found: {self.log_file}{Colors.ENDC}")
#             sys.exit(1)
#         except Exception as e:
#             print(f"{Colors.FAIL}[-] Error parsing log: {e}{Colors.ENDC}")
#             sys.exit(1)
        
#         print(f"{Colors.OKGREEN}[+] Parsed {len(entries)} log entries{Colors.ENDC}")
#         return entries
    
#     def detect_sql_injection(self, url):
#         """Detect SQL injection patterns"""
#         if not url:
#             return False
#         pattern = self.rules['sql_injection']['pattern']
#         return bool(re.search(pattern, url, re.IGNORECASE))
    
#     def detect_path_traversal(self, url):
#         """Detect path traversal patterns"""
#         if not url:
#             return False
#         pattern = self.rules['path_traversal']['pattern']
#         return bool(re.search(pattern, url, re.IGNORECASE))
    
#     def detect_xss(self, url):
#         """Detect XSS patterns"""
#         if not url:
#             return False
#         pattern = self.rules['xss']['pattern']
#         return bool(re.search(pattern, url, re.IGNORECASE))
    
#     def detect_command_injection(self, url):
#         """Detect command injection patterns"""
#         if not url:
#             return False
#         pattern = self.rules['command_injection']['pattern']
#         return bool(re.search(pattern, url, re.IGNORECASE))
    
#     def detect_brute_force(self, ip, status=None, message=None):
#         """Detect brute force attempts"""
#         current_time = datetime.now()
#         self.failed_login_timestamps[ip].append(current_time)
        
#         # Keep only last 10 seconds
#         self.failed_login_timestamps[ip] = [
#             t for t in self.failed_login_timestamps[ip] 
#             if (current_time - t).total_seconds() <= 10
#         ]
        
#         # Check if more than 5 failures in 10 seconds
#         if len(self.failed_login_timestamps[ip]) > 5:
#             self.failed_login_count[ip] += 1
#             return True
#         return False
    
#     def detect_suspicious_user_agent(self, user_agent):
#         """Detect suspicious user agents"""
#         if not user_agent:
#             return False
#         pattern = self.rules['suspicious_user_agent']['pattern']
#         return bool(re.search(pattern, user_agent, re.IGNORECASE))
    
#     def detect_attacks(self, entries):
#         """Detect attacks in log entries"""
#         print(f"{Colors.OKBLUE}[*] Analyzing for attacks...{Colors.ENDC}")
        
#         for entry in entries:
#             ip = entry.get('ip', 'Unknown')
#             url = entry.get('url', '')
#             status = entry.get('status', '')
#             user_agent = entry.get('user_agent', '')
            
#             alerts_found = []
            
#             # SQL Injection
#             if self.detect_sql_injection(url):
#                 alerts_found.append({
#                     'type': 'sql_injection',
#                     'severity': 'HIGH',
#                     'description': 'SQL Injection attempt detected',
#                     'ip': ip,
#                     'url': url[:100]
#                 })
            
#             # Path Traversal
#             if self.detect_path_traversal(url):
#                 alerts_found.append({
#                     'type': 'path_traversal',
#                     'severity': 'HIGH',
#                     'description': 'Path traversal attempt detected',
#                     'ip': ip,
#                     'url': url[:100]
#                 })
            
#             # XSS
#             if self.detect_xss(url):
#                 alerts_found.append({
#                     'type': 'xss',
#                     'severity': 'MEDIUM',
#                     'description': 'XSS attempt detected',
#                     'ip': ip,
#                     'url': url[:100]
#                 })
            
#             # Command Injection
#             if self.detect_command_injection(url):
#                 alerts_found.append({
#                     'type': 'command_injection',
#                     'severity': 'HIGH',
#                     'description': 'Command injection attempt',
#                     'ip': ip,
#                     'url': url[:100]
#                 })
            
#             # Brute Force (failed logins)
#             if status == '401' or 'Failed' in str(entry.get('message', '')):
#                 if self.detect_brute_force(ip, status):
#                     alerts_found.append({
#                         'type': 'brute_force',
#                         'severity': 'MEDIUM',
#                         'description': 'Brute force attempt (>5 failures in 10s)',
#                         'ip': ip,
#                         'count': len(self.failed_login_timestamps[ip])
#                     })
            
#             # Suspicious User Agent
#             if self.detect_suspicious_user_agent(user_agent):
#                 alerts_found.append({
#                     'type': 'suspicious_user_agent',
#                     'severity': 'MEDIUM',
#                     'description': 'Suspicious user agent detected',
#                     'ip': ip,
#                     'user_agent': user_agent[:50]
#                 })
            
#             # Add timestamp to alerts
#             for alert in alerts_found:
#                 alert['timestamp'] = entry.get('time', datetime.now()).isoformat()
#                 self.alerts.append(alert)
        
#         print(f"{Colors.OKGREEN}[+] Found {len(self.alerts)} alerts{Colors.ENDC}")
    
#     def display_alerts(self):
#         """Display alerts in color-coded table"""
#         if not self.alerts:
#             print(f"\n{Colors.OKGREEN}{'='*80}{Colors.ENDC}")
#             print(f"{Colors.OKGREEN}[✓] No attacks detected!{Colors.ENDC}")
#             print(f"{Colors.OKGREEN}{'='*80}{Colors.ENDC}")
#             return
        
#         print(f"\n{Colors.FAIL}{'='*120}{Colors.ENDC}")
#         print(f"{Colors.FAIL}⚠️⚠️⚠️  ATTACKS DETECTED!  ⚠️⚠️⚠️{Colors.ENDC}")
#         print(f"{Colors.FAIL}{'='*120}{Colors.ENDC}")
        
#         # Group by severity
#         high = [a for a in self.alerts if a['severity'] == 'HIGH']
#         medium = [a for a in self.alerts if a['severity'] == 'MEDIUM']
#         low = [a for a in self.alerts if a['severity'] == 'LOW']
        
#         # Display HIGH severity first
#         if high:
#             print(f"\n{Colors.FAIL}[!] HIGH SEVERITY:{Colors.ENDC}")
#             self.print_alert_table(high)
        
#         if medium:
#             print(f"\n{Colors.WARNING}[!] MEDIUM SEVERITY:{Colors.ENDC}")
#             self.print_alert_table(medium)
        
#         if low:
#             print(f"\n{Colors.DIM}[!] LOW SEVERITY:{Colors.ENDC}")
#             self.print_alert_table(low)
        
#         print(f"\n{Colors.FAIL}{'='*120}{Colors.ENDC}")
#         print(f"{Colors.FAIL}Total: {len(self.alerts)} alerts (High: {len(high)}, Medium: {len(medium)}, Low: {len(low)}){Colors.ENDC}")
    
#     def print_alert_table(self, alerts):
#         """Print alerts in table format"""
#         print(f"{Colors.HEADER}{'Timestamp':<25} {'IP':<18} {'Type':<20} {'Description':<40} {'Details':<25}{Colors.ENDC}")
#         print(f"{Colors.DIM}{'-'*120}{Colors.ENDC}")
        
#         for alert in alerts:
#             ts = alert.get('timestamp', 'N/A')[:19]
#             ip = alert.get('ip', 'Unknown')[:17]
#             atype = alert['type'][:19]
#             desc = alert['description'][:39]
#             details = ''
            
#             if 'url' in alert:
#                 details = alert['url'][:24]
#             elif 'user_agent' in alert:
#                 details = alert['user_agent'][:24]
#             elif 'count' in alert:
#                 details = f"Count: {alert['count']}"
            
#             # Color based on severity
#             if alert['severity'] == 'HIGH':
#                 color = Colors.FAIL
#             elif alert['severity'] == 'MEDIUM':
#                 color = Colors.WARNING
#             else:
#                 color = Colors.DIM
            
#             print(f"{color}{ts:<25} {ip:<18} {atype:<20} {desc:<40} {details:<25}{Colors.ENDC}")
    
#     def export_json(self, output_file):
#         """Export alerts to JSON"""
#         if not output_file:
#             return
        
#         try:
#             with open(output_file, 'w') as f:
#                 json.dump({
#                     'scan_info': {
#                         'timestamp': datetime.now().isoformat(),
#                         'log_file': self.log_file,
#                         'log_type': self.log_type,
#                         'total_alerts': len(self.alerts)
#                     },
#                     'alerts': self.alerts
#                 }, f, indent=2)
#             print(f"\n{Colors.OKGREEN}[+] Alerts exported to {output_file}{Colors.ENDC}")
#         except Exception as e:
#             print(f"{Colors.FAIL}[-] Failed to export: {e}{Colors.ENDC}")
    
#     def print_statistics(self):
#         """Print detection statistics"""
#         if not self.alerts:
#             return
        
#         print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
#         print(f"{Colors.BOLD}  DETECTION STATISTICS{Colors.ENDC}")
#         print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        
#         # Count by type
#         type_counts = defaultdict(int)
#         ip_counts = defaultdict(int)
        
#         for alert in self.alerts:
#             type_counts[alert['type']] += 1
#             ip_counts[alert.get('ip', 'Unknown')] += 1
        
#         print(f"\n{Colors.OKGREEN}Attack Types:{Colors.ENDC}")
#         for atype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
#             print(f"  {Colors.DIM}{atype}:{Colors.ENDC} {count}")
        
#         print(f"\n{Colors.OKGREEN}Top Attacker IPs:{Colors.ENDC}")
#         for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
#             print(f"  {Colors.FAIL}{ip}:{Colors.ENDC} {count} alerts")
        
#         print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
    
#     def run(self):
#         """Main execution"""
#         print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
#         print(f"{Colors.HEADER}  PROJECT #22 — Log Analysis & SIEM Simulator{Colors.ENDC}")
#         print(f"{Colors.OKBLUE}  ELK-style log analysis and attack detection{Colors.ENDC}")
#         print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
#         # Parse logs
#         entries = self.parse_log_file()
#         if not entries:
#             print(f"{Colors.WARNING}[!] No entries parsed{Colors.ENDC}")
#             return
        
#         # Detect attacks
#         self.detect_attacks(entries)
        
#         # Display results
#         self.display_alerts()
#         self.print_statistics()
        
#         return self.alerts

# def main():
#     parser = argparse.ArgumentParser(description="Log Analysis & SIEM Simulator")
#     parser.add_argument("--file", required=True, help="Log file to analyze")
#     parser.add_argument("--type", choices=['apache', 'syslog', 'evtx'], default='apache', 
#                         help="Log file type")
#     parser.add_argument("--rules", help="JSON rules file")
#     parser.add_argument("--output", help="Export alerts to JSON")
    
#     args = parser.parse_args()
    
#     analyzer = LogAnalyzer(args.file, args.type, args.rules)
#     alerts = analyzer.run()
    
#     if alerts and args.output:
#         analyzer.export_json(args.output)

# if __name__ == "__main__":
#     main()