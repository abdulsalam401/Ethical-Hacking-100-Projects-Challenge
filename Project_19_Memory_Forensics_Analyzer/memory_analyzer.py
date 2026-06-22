#!/usr/bin/env python3
"""
==============================================================
  PROJECT #19 — Memory Forensics Analyzer (Volatility-style)
  Process, Network, and Malware Detection Tool
==============================================================

FEATURES:
- Extract running processes (PID, PPID, command line)
- Extract network connections (TCP/UDP sockets)
- Detect suspicious indicators (malware names, hidden processes)
- Process tree visualization
- JSON report output
- Reduced false positives with regex matching

USAGE:
--------
  # Basic analysis (live system)
  python memory_analyzer.py
  
  # Save JSON report
  python memory_analyzer.py --output report.json
  
  # Verbose output
  python memory_analyzer.py --verbose
  
  # Process tree visualization
  python memory_analyzer.py --tree
==============================================================
"""

import psutil
import os
import sys
import socket
import json
import datetime
import platform
import re
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
    CYAN = Fore.CYAN

# Whitelist for legitimate Microsoft/Windows processes (reduces false positives)
WHITELIST_PROCESSES = {
    'code.exe', 'chrome.exe', 'msedge.exe', 'msedgewebview2.exe', 'firefox.exe',
    'powershell.exe', 'cmd.exe', 'explorer.exe', 'svchost.exe', 'services.exe',
    'winlogon.exe', 'csrss.exe', 'lsass.exe', 'wininit.exe', 'spoolsv.exe',
    'dwm.exe', 'taskhostw.exe', 'sihost.exe', 'fontdrvhost.exe', 'ctfmon.exe',
    'searchindexer.exe', 'runtimebroker.exe', 'startmenuexperiencehost.exe',
    'widgets.exe', 'snippingtool.exe', 'idmintegrator64.exe', 'wslrelay.exe',
    'openconsole.exe', 'grammarly.desktop.exe', 'superhuman.webui.exe',
    'mysqld.exe', 'vmmemwsl', 'wslhost.exe', 'conhost.exe'
}

# Malicious process indicators (using regex for exact matching)
MALICIOUS_PATTERNS = {
    # Reverse shells - full executable names
    r'^nc\.exe$': 'Netcat reverse shell (Windows)',
    r'^ncat\.exe$': 'Ncat reverse shell',
    r'^socat\.exe$': 'Socat reverse shell',
    r'^powercat\.ps1$': 'PowerShell reverse shell',
    
    # Password dumpers
    r'^mimikatz\.exe$': 'Credential dumper - Windows password extractor',
    r'^procdump\.exe$': 'Process dumper - often used for LSASS dumping',
    r'lsass\.dmp': 'LSASS memory dump - credential theft indicator',
    
    # Remote access tools (suspicious if not expected)
    r'^vnc\.exe$': 'VNC remote access (unexpected)',
    r'^tightvnc\.exe$': 'TightVNC remote access',
    r'^ultravnc\.exe$': 'UltraVNC remote access',
    r'^teamviewer_[0-9]+\.exe$': 'TeamViewer (unexpected)',
    
    # Crypto miners
    r'^xmrig\.exe$': 'XMRig cryptominer',
    r'^minerd\.exe$': 'Minerd cryptominer',
    r'^cgminer\.exe$': 'CGMiner cryptominer',
    r'^bfgminer\.exe$': 'BFGMiner cryptominer',
    
    # Exploit tools
    r'meterpreter': 'Metasploit Meterpreter payload',
    r'beacon\.exe$': 'Cobalt Strike beacon',
    r'^mimikittenz\.ps1': 'Mimikittenz PowerShell credential stealer',
    
    # Post-exploitation
    r'^winpeas\.exe$': 'WinPEAS privilege escalation checker',
    r'^linpeas\.sh$': 'LinPEAS privilege escalation checker',
    r'^sharpup\.exe$': 'SharpUp privilege escalation',
    r'^seatbelt\.exe$': 'Seatbelt security checker (often malicious)',
    
    # Suspicious command patterns
    r'powershell\s+.*-enc\s+': 'Encoded PowerShell command (suspicious)',
    r'powershell\s+.*-e\s+[A-Za-z0-9+/=]{20,}': 'Base64 encoded PowerShell (highly suspicious)',
    r'cmd\.exe\s+/c\s+(?:powershell|wmic|rundll32)': 'Suspicious cmd execution pattern',
    r'rundll32\.exe\s+.*,.*#\d+': 'Rundll32 suspicious export pattern',
    
    # LOLBins (Living off the land)
    r'wmic\.exe\s+process\s+call\s+create': 'WMIC process creation (often malicious)',
    r'regsvr32\.exe\s+/s\s+/u\s+/i:': 'Regsvr32 script execution (malicious pattern)',
    r'mshta\.exe\s+javascript:': 'MSHTA JavaScript execution (often malware)',
}

# Suspicious ports (with context)
SUSPICIOUS_PORTS = {
    21: 'FTP (cleartext - data exfiltration risk)',
    22: 'SSH (monitor for reverse tunnels)',
    23: 'Telnet (insecure, rarely legitimate)',
    4443: 'Metasploit reverse shell (common)',
    4444: 'Metasploit reverse shell (common)',
    5555: 'Android debug bridge (reverse shell potential)',
    6666: 'IRC botnet (common)',
    6667: 'IRC botnet (common)',
    7777: 'Reverse shell (common port)',
    8888: 'Proxy/backdoor (common)',
    9999: 'Reverse shell (common)',
    1337: 'Elite backdoor port (common)',
    31337: 'Backdoor port (leet speak)',
    3389: 'RDP (monitor for lateral movement)',
    5985: 'WinRM (lateral movement potential)',
    5986: 'WinRM HTTPS (lateral movement)',
}

# Known legitimate external services (whitelist)
LEGITIMATE_IPS = [
    'google.com', 'microsoft.com', 'windows.com', 'azure.com', 'aws.amazon.com',
    'cloudflare.com', 'github.com', 'facebook.com', 'instagram.com', 'whatsapp.net',
    'telegram.org', 'discord.com', 'slack.com', 'zoom.us', 'teams.microsoft.com'
]

class MemoryForensicsAnalyzer:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.processes = []
        self.network_connections = []
        self.suspicious_items = []
        self.process_tree = defaultdict(list)
        
    def is_admin(self):
        """Check if running with admin/root privileges"""
        if platform.system() == 'Windows':
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
        else:
            try:
                return os.geteuid() == 0
            except:
                return False
    
    def is_whitelisted_process(self, name):
        """Check if process is in whitelist (reduces false positives)"""
        name_lower = name.lower()
        return name_lower in WHITELIST_PROCESSES
    
    def is_suspicious_process(self, name, cmdline):
        """Check if process is suspicious using regex patterns"""
        name_lower = name.lower()
        cmdline_lower = cmdline.lower()
        
        # Skip whitelisted processes (reduces false positives)
        if self.is_whitelisted_process(name_lower):
            return False, None, None
        
        # Check against malicious patterns
        for pattern, description in MALICIOUS_PATTERNS.items():
            # Check in process name
            if re.search(pattern, name_lower, re.IGNORECASE):
                return True, pattern, description
            # Check in command line
            if re.search(pattern, cmdline_lower, re.IGNORECASE):
                return True, pattern, description
        
        # Additional checks for suspicious command line flags
        suspicious_flags = ['-enc', '-e JAB', ' -w hidden', ' -windowstyle hidden', 
                           ' -ExecutionPolicy Bypass', ' -NoProfile', ' -NonInteractive']
        for flag in suspicious_flags:
            if flag.lower() in cmdline_lower:
                return True, flag, f"Suspicious PowerShell flag: {flag}"
        
        return False, None, None
    
    def is_suspicious_port(self, port):
        """Check if port is suspicious"""
        return port in SUSPICIOUS_PORTS
    
    def is_legitimate_connection(self, remote_ip):
        """Check if remote connection is to legitimate services"""
        # Localhost connections are normal
        if remote_ip.startswith('127.') or remote_ip == 'localhost':
            return True
        
        # Private IP ranges are internal
        if (remote_ip.startswith('10.') or 
            remote_ip.startswith('172.') or 
            remote_ip.startswith('192.168.')):
            return True
        
        # Check against known legitimate domains
        try:
            for legit_domain in LEGITIMATE_IPS:
                try:
                    ip = socket.gethostbyname(legit_domain)
                    if remote_ip == ip:
                        return True
                except:
                    continue
        except:
            pass
        
        return False
    
    def banner(self):
        """Display banner"""
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}  PROJECT #19 — Memory Forensics Analyzer (Volatility-style){Colors.ENDC}")
        print(f"{Colors.OKBLUE}  Process, Network, and Malware Detection{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        print(f"{Colors.OKGREEN}[+] System: {platform.system()} {platform.release()}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Hostname: {socket.gethostname()}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
        
        if not self.is_admin():
            print(f"{Colors.WARNING}[!] Running without admin/root privileges. Some process details may be unavailable.{Colors.ENDC}")
            if platform.system() != 'Windows':
                print(f"{Colors.DIM}    For full analysis, run with: sudo python3 memory_analyzer.py{Colors.ENDC}")
        print()
    
    def get_all_processes(self):
        """Get all running processes"""
        processes = []
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline', 
                                          'create_time', 'username', 'memory_info',
                                          'cpu_percent', 'status']):
            try:
                info = proc.info
                processes.append({
                    'pid': info['pid'],
                    'ppid': info['ppid'],
                    'name': info['name'] or 'Unknown',
                    'cmdline': ' '.join(info['cmdline']) if info['cmdline'] else '',
                    'create_time': datetime.datetime.fromtimestamp(
                        info['create_time']).strftime('%Y-%m-%d %H:%M:%S') if info['create_time'] else 'N/A',
                    'username': info['username'] or 'N/A',
                    'memory_mb': info['memory_info'].rss / 1024 / 1024 if info['memory_info'] else 0,
                    'cpu_percent': info['cpu_percent'] or 0,
                    'status': info['status'] or 'Unknown'
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return sorted(processes, key=lambda x: x['memory_mb'], reverse=True)
    
    def get_network_connections(self):
        """Get all network connections"""
        connections = []
        
        try:
            # TCP connections
            for conn in psutil.net_connections(kind='tcp'):
                try:
                    conn_info = {
                        'protocol': 'TCP',
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '*:*',
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '*:*',
                        'status': conn.status,
                        'pid': conn.pid,
                        'process': self.get_process_name(conn.pid) if conn.pid else 'N/A'
                    }
                    connections.append(conn_info)
                except:
                    continue
            
            # UDP connections
            for conn in psutil.net_connections(kind='udp'):
                try:
                    conn_info = {
                        'protocol': 'UDP',
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '*:*',
                        'remote_addr': '*:*',
                        'status': 'LISTEN',
                        'pid': conn.pid,
                        'process': self.get_process_name(conn.pid) if conn.pid else 'N/A'
                    }
                    connections.append(conn_info)
                except:
                    continue
        except psutil.AccessDenied:
            print(f"{Colors.WARNING}[!] Access denied for network connections. Run with admin privileges.{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.DIM}[!] Error getting network connections: {e}{Colors.ENDC}")
        
        return connections
    
    def get_process_name(self, pid):
        """Get process name by PID"""
        try:
            return psutil.Process(pid).name()
        except:
            return 'Unknown'
    
    def build_process_tree(self, processes):
        """Build process tree structure"""
        tree = defaultdict(list)
        for proc in processes:
            tree[proc['ppid']].append(proc)
        return tree
    
    def print_process_tree(self, tree, parent_pid=0, level=0):
        """Print process tree visualization"""
        indent = '  ' * level
        for proc in sorted(tree.get(parent_pid, []), key=lambda x: x['name']):
            # Color based on process name
            is_susp, _, _ = self.is_suspicious_process(proc['name'], proc['cmdline'])
            if is_susp:
                color = Colors.FAIL
            elif proc['memory_mb'] > 500:
                color = Colors.WARNING
            else:
                color = Colors.OKGREEN
            
            print(f"{indent}{color}├── {proc['name']} ({proc['pid']}) - {proc['memory_mb']:.1f}MB{Colors.ENDC}")
            self.print_process_tree(tree, proc['pid'], level + 1)
    
    def analyze_suspicious_indicators(self, processes, connections):
        """Detect malicious indicators"""
        suspicious = []
        
        # Check processes
        for proc in processes:
            is_susp, pattern, description = self.is_suspicious_process(proc['name'], proc['cmdline'])
            if is_susp:
                suspicious.append({
                    'type': 'PROCESS',
                    'indicator': pattern,
                    'description': description,
                    'pid': proc['pid'],
                    'name': proc['name'],
                    'cmdline': proc['cmdline'][:200],
                    'severity': 'HIGH'
                })
                if self.verbose:
                    print(f"{Colors.FAIL}[!] Suspicious process: {proc['name']} (PID: {proc['pid']}){Colors.ENDC}")
        
        # Check network connections
        for conn in connections:
            # Check local ports
            if conn['local_addr'] != '*:*':
                try:
                    port = int(conn['local_addr'].split(':')[-1])
                    if self.is_suspicious_port(port):
                        suspicious.append({
                            'type': 'NETWORK',
                            'indicator': f"Port {port}",
                            'description': SUSPICIOUS_PORTS.get(port, 'Suspicious port listening'),
                            'pid': conn['pid'],
                            'process': conn['process'],
                            'local_addr': conn['local_addr'],
                            'severity': 'MEDIUM'
                        })
                except:
                    pass
            
            # Check remote addresses for suspicious connections
            if conn['remote_addr'] != '*:*' and conn['status'] == 'ESTABLISHED':
                remote_ip = conn['remote_addr'].split(':')[0]
                
                # Skip legitimate connections
                if self.is_legitimate_connection(remote_ip):
                    continue
                
                # Check for connections to known malicious ports
                try:
                    remote_port = int(conn['remote_addr'].split(':')[-1])
                    if remote_port in SUSPICIOUS_PORTS:
                        suspicious.append({
                            'type': 'REVERSE_SHELL',
                            'indicator': f"External connection to {conn['remote_addr']}",
                            'description': f"Possible C2 communication - {SUSPICIOUS_PORTS.get(remote_port, 'Suspicious port')}",
                            'pid': conn['pid'],
                            'process': conn['process'],
                            'remote_addr': conn['remote_addr'],
                            'severity': 'HIGH'
                        })
                    else:
                        # Unknown external connection
                        suspicious.append({
                            'type': 'SUSPICIOUS_CONNECTION',
                            'indicator': f"External connection to {conn['remote_addr']}",
                            'description': 'Unknown external connection - investigate if unexpected',
                            'pid': conn['pid'],
                            'process': conn['process'],
                            'remote_addr': conn['remote_addr'],
                            'severity': 'LOW'
                        })
                except:
                    pass
        
        return suspicious
    
    def print_processes_table(self, processes):
        """Print processes in table format"""
        print(f"\n{Colors.HEADER}{'='*120}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'PID':<8} {'PPID':<8} {'Name':<30} {'Memory(MB)':<12} {'CPU%':<8} {'User':<20} {'Status':<10}{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*120}{Colors.ENDC}")
        
        suspicious_count = 0
        for proc in processes[:30]:  # Show top 30 processes
            # Color based on suspicion
            is_susp, _, _ = self.is_suspicious_process(proc['name'], proc['cmdline'])
            if is_susp:
                name_color = Colors.FAIL
                status_color = Colors.FAIL
                suspicious_count += 1
            elif proc['memory_mb'] > 500:
                name_color = Colors.WARNING
                status_color = Colors.WARNING
            else:
                name_color = Colors.CYAN
                status_color = Colors.DIM
            
            # Truncate username if too long
            username = proc['username'][:19] if len(proc['username']) > 19 else proc['username']
            
            print(f"{proc['pid']:<8} {proc['ppid']:<8} "
                  f"{name_color}{proc['name'][:29]:<30}{Colors.ENDC} "
                  f"{proc['memory_mb']:<12.1f} "
                  f"{proc['cpu_percent']:<8.1f} "
                  f"{Colors.DIM}{username:<20}{Colors.ENDC} "
                  f"{status_color}{proc['status']:<10}{Colors.ENDC}")
        
        if len(processes) > 30:
            print(f"{Colors.DIM}... and {len(processes)-30} more processes{Colors.ENDC}")
        
        print(f"{Colors.HEADER}{'='*120}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Total processes: {len(processes)} (Suspicious: {suspicious_count}){Colors.ENDC}")
    
    def print_network_table(self, connections):
        """Print network connections in table format"""
        print(f"\n{Colors.HEADER}{'='*110}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'Protocol':<8} {'Local Address':<30} {'Remote Address':<30} {'Status':<12} {'PID':<8} {'Process':<20}{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*110}{Colors.ENDC}")
        
        # Filter to show established connections and listeners
        important_conns = [c for c in connections if c['status'] in ['ESTABLISHED', 'LISTEN']]
        
        if not important_conns:
            print(f"{Colors.DIM}No active network connections found{Colors.ENDC}")
        else:
            suspicious_conns = 0
            for conn in important_conns[:25]:
                # Color based on status
                if conn['status'] == 'ESTABLISHED':
                    status_color = Colors.WARNING
                elif conn['status'] == 'LISTEN':
                    status_color = Colors.OKGREEN
                else:
                    status_color = Colors.DIM
                
                # Check for suspicious ports
                try:
                    port = int(conn['local_addr'].split(':')[-1]) if conn['local_addr'] != '*:*' else 0
                    if self.is_suspicious_port(port):
                        protocol_color = Colors.FAIL
                        suspicious_conns += 1
                    else:
                        protocol_color = Colors.OKBLUE
                except:
                    protocol_color = Colors.DIM
                
                print(f"{protocol_color}{conn['protocol']:<8}{Colors.ENDC} "
                      f"{Colors.DIM}{conn['local_addr'][:29]:<30}{Colors.ENDC} "
                      f"{Colors.DIM}{conn['remote_addr'][:29]:<30}{Colors.ENDC} "
                      f"{status_color}{conn['status']:<12}{Colors.ENDC} "
                      f"{conn['pid']:<8} "
                      f"{Colors.DIM}{conn['process'][:19]:<20}{Colors.ENDC}")
            
            if len(important_conns) > 25:
                print(f"{Colors.DIM}... and {len(important_conns)-25} more connections{Colors.ENDC}")
            
            print(f"{Colors.HEADER}{'='*110}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}Total connections: {len(connections)} (ESTABLISHED: {len([c for c in connections if c['status']=='ESTABLISHED'])}, LISTEN: {len([c for c in connections if c['status']=='LISTEN'])}, Suspicious: {suspicious_conns}){Colors.ENDC}")
    
    def print_suspicious_table(self, suspicious):
        """Print suspicious findings"""
        if not suspicious:
            print(f"\n{Colors.OKGREEN}{'='*100}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[✓] No suspicious indicators found! System appears clean.{Colors.ENDC}")
            print(f"{Colors.OKGREEN}{'='*100}{Colors.ENDC}")
            return
        
        # Separate by severity
        high_severity = [s for s in suspicious if s.get('severity') == 'HIGH']
        medium_severity = [s for s in suspicious if s.get('severity') == 'MEDIUM']
        low_severity = [s for s in suspicious if s.get('severity') == 'LOW']
        
        print(f"\n{Colors.FAIL}{'='*100}{Colors.ENDC}")
        print(f"{Colors.FAIL}⚠️⚠️⚠️  SUSPICIOUS INDICATORS DETECTED!  ⚠️⚠️⚠️{Colors.ENDC}")
        print(f"{Colors.FAIL}{'='*100}{Colors.ENDC}")
        
        # High severity
        if high_severity:
            print(f"\n{Colors.FAIL}[!] HIGH SEVERITY - Investigate Immediately:{Colors.ENDC}")
            for item in high_severity:
                print(f"\n  {Colors.FAIL}▶ {item['type']}{Colors.ENDC}")
                print(f"    Indicator: {Colors.WARNING}{item['indicator']}{Colors.ENDC}")
                print(f"    Description: {Colors.DIM}{item['description']}{Colors.ENDC}")
                print(f"    Process: {item.get('process', item.get('name', 'N/A'))}")
                print(f"    PID: {item.get('pid', 'N/A')}")
                if 'cmdline' in item and item['cmdline']:
                    print(f"    Command: {item['cmdline'][:150]}...")
                if 'remote_addr' in item:
                    print(f"    Remote: {item['remote_addr']}")
        
        # Medium severity
        if medium_severity:
            print(f"\n{Colors.WARNING}[!] MEDIUM SEVERITY - Monitor:{Colors.ENDC}")
            for item in medium_severity[:10]:
                print(f"    • {item['indicator']} - {item['description']}")
                print(f"      Process: {item.get('process', item.get('name', 'N/A'))} (PID: {item.get('pid', 'N/A')})")
            if len(medium_severity) > 10:
                print(f"    ... and {len(medium_severity)-10} more medium severity items")
        
        # Low severity
        if low_severity:
            print(f"\n{Colors.DIM}[!] LOW SEVERITY - Review if needed:{Colors.ENDC}")
            for item in low_severity[:5]:
                print(f"    • {item['indicator']}")
            if len(low_severity) > 5:
                print(f"    ... and {len(low_severity)-5} more low severity items")
        
        print(f"\n{Colors.FAIL}{'='*100}{Colors.ENDC}")
        print(f"{Colors.FAIL}Total suspicious indicators: {len(suspicious)} (High: {len(high_severity)}, Medium: {len(medium_severity)}, Low: {len(low_severity)}){Colors.ENDC}")
        
        # Note about false positives
        print(f"\n{Colors.DIM}Note: Some indicators may be false positives. Review each item carefully.{Colors.ENDC}")
    
    def save_json_report(self, processes, connections, suspicious, output_file):
        """Save analysis results to JSON"""
        report = {
            'scan_info': {
                'timestamp': datetime.datetime.now().isoformat(),
                'hostname': socket.gethostname(),
                'system': f"{platform.system()} {platform.release()}",
                'total_processes': len(processes),
                'total_connections': len(connections),
                'suspicious_count': len(suspicious),
                'admin_mode': self.is_admin()
            },
            'processes': processes[:100],  # Top 100 processes
            'network_connections': connections[:50],  # Top 50 connections
            'suspicious_indicators': suspicious
        }
        
        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n{Colors.OKGREEN}[+] Report saved to {output_file}{Colors.ENDC}")
        except Exception as e:
            print(f"\n{Colors.FAIL}[-] Failed to save report: {e}{Colors.ENDC}")
    
    def print_summary(self, processes, connections, suspicious):
        """Print summary statistics"""
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}  FORENSICS SUMMARY{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        
        # Process statistics
        total_memory = sum(p['memory_mb'] for p in processes)
        total_cpu = sum(p['cpu_percent'] for p in processes)
        
        print(f"\n{Colors.OKGREEN}Process Statistics:{Colors.ENDC}")
        print(f"  Total processes: {len(processes)}")
        print(f"  Total memory usage: {total_memory:.1f} MB ({total_memory/1024:.2f} GB)")
        print(f"  Total CPU usage: {total_cpu:.1f}%")
        
        # Top memory consumers
        print(f"\n{Colors.OKGREEN}Top 5 Memory Consumers:{Colors.ENDC}")
        for i, proc in enumerate(processes[:5], 1):
            is_susp, _, _ = self.is_suspicious_process(proc['name'], proc['cmdline'])
            if is_susp:
                color = Colors.FAIL
            else:
                color = Colors.DIM
            print(f"  {i}. {color}{proc['name']}{Colors.ENDC} - {proc['memory_mb']:.1f} MB")
        
        # Network statistics
        established = len([c for c in connections if c['status'] == 'ESTABLISHED'])
        listening = len([c for c in connections if c['status'] == 'LISTEN'])
        
        print(f"\n{Colors.OKGREEN}Network Statistics:{Colors.ENDC}")
        print(f"  Total connections: {len(connections)}")
        print(f"  Established: {established}")
        print(f"  Listening: {listening}")
        
        # Suspicious counts
        if suspicious:
            high_count = len([s for s in suspicious if s.get('severity') == 'HIGH'])
            medium_count = len([s for s in suspicious if s.get('severity') == 'MEDIUM'])
            low_count = len([s for s in suspicious if s.get('severity') == 'LOW'])
            
            print(f"\n{Colors.OKGREEN}Suspicious Indicators:{Colors.ENDC}")
            print(f"  Total: {len(suspicious)}")
            print(f"  High Severity: {high_count}")
            print(f"  Medium Severity: {medium_count}")
            print(f"  Low Severity: {low_count}")
            
            if high_count == 0 and medium_count == 0:
                print(f"\n{Colors.OKGREEN}[✓] No high or medium severity threats detected!{Colors.ENDC}")
        else:
            print(f"\n{Colors.OKGREEN}[✓] No suspicious indicators found!{Colors.ENDC}")
        
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
    
    def print_defenses(self):
        """Print defense mechanisms against memory forensics"""
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}  DEFENSE AGAINST MEMORY FORENSICS{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        
        defenses = [
            ("Process Hiding (DKOM)", "Remove process from EPROCESS list - Detected via process listing discrepancies"),
            ("Code Injection", "Inject into legitimate processes - Monitored via memory region analysis"),
            ("Rootkits", "Hook system calls, hide network connections - Detected via API hook scanning"),
            ("Anti-forensics", "Wipe memory, encrypt data before exit - Look for rapid process termination"),
            ("Living off the land", "Use legitimate Windows/Linux tools - Monitor for suspicious command lines"),
            ("Packer/Crypters", "Obfuscate executable signatures - Check entropy and section names"),
            ("Reflective DLL Injection", "Load DLL from memory without disk write - Scan for RWX memory regions"),
            ("Process Hollowing", "Replace legitimate process memory - Compare PE headers in memory vs disk"),
            ("Memory Encryption", "Encrypt sensitive data in memory - Look for cryptographic API usage"),
            ("Fast Exit", "Delete artifacts before termination - Monitor process creation/destruction events")
        ]
        
        for title, desc in defenses:
            print(f"{Colors.OKGREEN}{title}{Colors.ENDC}: {Colors.DIM}{desc}{Colors.ENDC}")
        
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Memory Forensics Analyzer")
    parser.add_argument("-o", "--output", help="Save JSON report to file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-t", "--tree", action="store_true", help="Show process tree")
    
    args = parser.parse_args()
    
    # Create analyzer
    analyzer = MemoryForensicsAnalyzer(verbose=args.verbose)
    
    # Display banner
    analyzer.banner()
    
    # Get data
    print(f"{Colors.OKBLUE}[*] Analyzing processes...{Colors.ENDC}")
    processes = analyzer.get_all_processes()
    print(f"{Colors.OKGREEN}[+] Found {len(processes)} processes{Colors.ENDC}")
    
    print(f"{Colors.OKBLUE}[*] Analyzing network connections...{Colors.ENDC}")
    connections = analyzer.get_network_connections()
    print(f"{Colors.OKGREEN}[+] Found {len(connections)} network connections{Colors.ENDC}")
    
    print(f"{Colors.OKBLUE}[*] Detecting suspicious indicators...{Colors.ENDC}")
    suspicious = analyzer.analyze_suspicious_indicators(processes, connections)
    
    # Display results
    analyzer.print_processes_table(processes)
    
    if args.tree:
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}  PROCESS TREE VISUALIZATION{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        tree = analyzer.build_process_tree(processes)
        analyzer.print_process_tree(tree)
    
    analyzer.print_network_table(connections)
    analyzer.print_suspicious_table(suspicious)
    analyzer.print_summary(processes, connections, suspicious)
    
    # Save JSON report
    if args.output:
        analyzer.save_json_report(processes, connections, suspicious, args.output)
    
    # Print defense documentation
    if args.verbose:
        analyzer.print_defenses()

if __name__ == "__main__":
    main()


# #!/usr/bin/env python3
# """
# ==============================================================
#   PROJECT #19 — Memory Forensics Analyzer (Volatility-style)
#   Process, Network, and Malware Detection Tool
# ==============================================================

# FEATURES:
# - Extract running processes (PID, PPID, command line)
# - Extract network connections (TCP/UDP sockets)
# - Detect suspicious indicators (malware names, hidden processes)
# - Process tree visualization
# - JSON report output

# USAGE:
# --------
#   # Basic analysis (live system)
#   python memory_analyzer.py
  
#   # Save JSON report
#   python memory_analyzer.py --output report.json
  
#   # Verbose output
#   python memory_analyzer.py --verbose
  
#   # Process tree visualization
#   python memory_analyzer.py --tree
# ==============================================================
# """

# import psutil
# import os
# import sys
# import socket
# import json
# import datetime
# import platform
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
#     CYAN = Fore.CYAN  # Added missing CYAN

# # Malicious process indicators
# MALICIOUS_PROCESSES = {
#     # Reverse shells
#     'nc.exe': 'Netcat reverse shell',
#     'ncat.exe': 'Ncat reverse shell',
#     'socat': 'Socat reverse shell',
#     'powercat': 'PowerShell reverse shell',
#     'nc': 'Netcat reverse shell (Linux)',
    
#     # Password dumpers
#     'mimikatz.exe': 'Credential dumper',
#     'procdump.exe': 'Process dumper',
#     'lsass.dmp': 'LSASS memory dump',
    
#     # Remote access tools
#     'vnc.exe': 'VNC remote access',
#     'teamviewer': 'Remote access tool',
#     'anydesk': 'Remote access tool',
#     'radmin': 'Remote admin tool',
    
#     # Crypto miners
#     'xmrig.exe': 'Cryptominer',
#     'minerd': 'Cryptominer',
#     'cgminer': 'Cryptominer',
    
#     # Exploit tools
#     'meterpreter': 'Metasploit payload',
#     'beacon.exe': 'Cobalt Strike beacon',
#     'powershell -enc': 'Encoded PowerShell',
#     'powershell -e': 'Encoded PowerShell',
#     'cmd.exe /c': 'Suspicious cmd execution',
#     'python -c': 'Python one-liner (possible payload)',
    
#     # Post-exploitation
#     'winpeas': 'Privilege escalation checker',
#     'linpeas': 'Privilege escalation checker',
#     'sharpup': 'Privilege escalation',
# }

# # Suspicious ports
# SUSPICIOUS_PORTS = {
#     21: 'FTP (cleartext)',
#     22: 'SSH (monitor for reverse tunnels)',
#     23: 'Telnet (insecure)',
#     4443: 'Metasploit reverse shell',
#     4444: 'Metasploit reverse shell',
#     5555: 'Android debug bridge (reverse shell)',
#     6666: 'IRC botnet',
#     6667: 'IRC botnet',
#     7777: 'Reverse shell common',
#     8888: 'Proxy/backdoor',
#     9999: 'Reverse shell common',
#     1337: 'Common backdoor port',
#     31337: 'Backdoor port',
#     3389: 'RDP (monitor for pivoting)',
#     5985: 'WinRM (lateral movement)',
#     5986: 'WinRM (lateral movement)',
# }

# class MemoryForensicsAnalyzer:
#     def __init__(self, verbose=False):
#         self.verbose = verbose
#         self.processes = []
#         self.network_connections = []
#         self.suspicious_items = []
#         self.process_tree = defaultdict(list)
        
#     def is_admin(self):
#         """Check if running with admin/root privileges"""
#         if platform.system() == 'Windows':
#             try:
#                 import ctypes
#                 return ctypes.windll.shell32.IsUserAnAdmin() != 0
#             except:
#                 return False
#         else:
#             try:
#                 return os.geteuid() == 0
#             except:
#                 return False
        
#     def banner(self):
#         """Display banner"""
#         print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
#         print(f"{Colors.HEADER}  PROJECT #19 — Memory Forensics Analyzer (Volatility-style){Colors.ENDC}")
#         print(f"{Colors.OKBLUE}  Process, Network, and Malware Detection{Colors.ENDC}")
#         print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
#         print(f"{Colors.OKGREEN}[+] System: {platform.system()} {platform.release()}{Colors.ENDC}")
#         print(f"{Colors.OKGREEN}[+] Hostname: {socket.gethostname()}{Colors.ENDC}")
#         print(f"{Colors.OKGREEN}[+] Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
#         print(f"{Colors.OKGREEN}[+] Total processes: {len(self.get_all_processes())}{Colors.ENDC}")
        
#         if not self.is_admin():
#             print(f"{Colors.WARNING}[!] Running without admin/root privileges. Some process details may be unavailable.{Colors.ENDC}")
#             if platform.system() != 'Windows':
#                 print(f"{Colors.DIM}    For full analysis, run with: sudo python3 memory_analyzer.py{Colors.ENDC}")
#         print()
    
#     def get_all_processes(self):
#         """Get all running processes"""
#         processes = []
#         for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline', 
#                                           'create_time', 'username', 'memory_info',
#                                           'cpu_percent', 'status']):
#             try:
#                 info = proc.info
#                 processes.append({
#                     'pid': info['pid'],
#                     'ppid': info['ppid'],
#                     'name': info['name'] or 'Unknown',
#                     'cmdline': ' '.join(info['cmdline']) if info['cmdline'] else '',
#                     'create_time': datetime.datetime.fromtimestamp(
#                         info['create_time']).strftime('%Y-%m-%d %H:%M:%S') if info['create_time'] else 'N/A',
#                     'username': info['username'] or 'N/A',
#                     'memory_mb': info['memory_info'].rss / 1024 / 1024 if info['memory_info'] else 0,
#                     'cpu_percent': info['cpu_percent'] or 0,
#                     'status': info['status'] or 'Unknown'
#                 })
#             except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
#                 continue
#         return sorted(processes, key=lambda x: x['memory_mb'], reverse=True)
    
#     def get_network_connections(self):
#         """Get all network connections"""
#         connections = []
        
#         try:
#             # TCP connections
#             for conn in psutil.net_connections(kind='tcp'):
#                 try:
#                     conn_info = {
#                         'protocol': 'TCP',
#                         'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '*:*',
#                         'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '*:*',
#                         'status': conn.status,
#                         'pid': conn.pid,
#                         'process': self.get_process_name(conn.pid) if conn.pid else 'N/A'
#                     }
#                     connections.append(conn_info)
#                 except:
#                     continue
            
#             # UDP connections
#             for conn in psutil.net_connections(kind='udp'):
#                 try:
#                     conn_info = {
#                         'protocol': 'UDP',
#                         'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '*:*',
#                         'remote_addr': '*:*',
#                         'status': 'LISTEN',
#                         'pid': conn.pid,
#                         'process': self.get_process_name(conn.pid) if conn.pid else 'N/A'
#                     }
#                     connections.append(conn_info)
#                 except:
#                     continue
#         except psutil.AccessDenied:
#             print(f"{Colors.WARNING}[!] Access denied for network connections. Run with admin privileges.{Colors.ENDC}")
#         except Exception as e:
#             print(f"{Colors.DIM}[!] Error getting network connections: {e}{Colors.ENDC}")
        
#         return connections
    
#     def get_process_name(self, pid):
#         """Get process name by PID"""
#         try:
#             return psutil.Process(pid).name()
#         except:
#             return 'Unknown'
    
#     def build_process_tree(self, processes):
#         """Build process tree structure"""
#         tree = defaultdict(list)
#         for proc in processes:
#             tree[proc['ppid']].append(proc)
#         return tree
    
#     def print_process_tree(self, tree, parent_pid=0, level=0):
#         """Print process tree visualization"""
#         indent = '  ' * level
#         for proc in sorted(tree.get(parent_pid, []), key=lambda x: x['name']):
#             # Color based on process name
#             if self.is_suspicious_process(proc['name'], proc['cmdline']):
#                 color = Colors.FAIL
#             elif proc['memory_mb'] > 500:
#                 color = Colors.WARNING
#             else:
#                 color = Colors.OKGREEN
            
#             print(f"{indent}{color}├── {proc['name']} ({proc['pid']}) - {proc['memory_mb']:.1f}MB{Colors.ENDC}")
#             self.print_process_tree(tree, proc['pid'], level + 1)
    
#     def is_suspicious_process(self, name, cmdline):
#         """Check if process is suspicious"""
#         name_lower = name.lower()
#         cmdline_lower = cmdline.lower()
        
#         for indicator, description in MALICIOUS_PROCESSES.items():
#             if indicator.lower() in name_lower or indicator.lower() in cmdline_lower:
#                 return True
#         return False
    
#     def is_suspicious_port(self, port):
#         """Check if port is suspicious"""
#         return port in SUSPICIOUS_PORTS
    
#     def analyze_suspicious_indicators(self, processes, connections):
#         """Detect malicious indicators"""
#         suspicious = []
        
#         # Check processes
#         for proc in processes:
#             name_lower = proc['name'].lower()
#             cmdline_lower = proc['cmdline'].lower()
            
#             for indicator, description in MALICIOUS_PROCESSES.items():
#                 if indicator.lower() in name_lower or indicator.lower() in cmdline_lower:
#                     suspicious.append({
#                         'type': 'PROCESS',
#                         'indicator': indicator,
#                         'description': description,
#                         'pid': proc['pid'],
#                         'name': proc['name'],
#                         'cmdline': proc['cmdline'][:200]
#                     })
#                     break
        
#         # Check network connections
#         for conn in connections:
#             if conn['local_addr'] != '*:*':
#                 try:
#                     port = int(conn['local_addr'].split(':')[-1])
#                     if self.is_suspicious_port(port):
#                         suspicious.append({
#                             'type': 'NETWORK',
#                             'indicator': f"Port {port}",
#                             'description': SUSPICIOUS_PORTS.get(port, 'Suspicious port'),
#                             'pid': conn['pid'],
#                             'process': conn['process'],
#                             'local_addr': conn['local_addr']
#                         })
#                 except:
#                     pass
            
#             # Check remote addresses (reverse shells)
#             if conn['remote_addr'] != '*:*' and conn['status'] == 'ESTABLISHED':
#                 if conn['remote_addr'].startswith(('192.168.', '10.', '172.')):
#                     # Internal connections - might be normal
#                     pass
#                 else:
#                     suspicious.append({
#                         'type': 'REVERSE_SHELL',
#                         'indicator': f"External connection from {conn['remote_addr']}",
#                         'description': 'Possible reverse shell or C2 communication',
#                         'pid': conn['pid'],
#                         'process': conn['process'],
#                         'remote_addr': conn['remote_addr']
#                     })
        
#         return suspicious
    
#     def print_processes_table(self, processes):
#         """Print processes in table format"""
#         print(f"\n{Colors.HEADER}{'='*120}{Colors.ENDC}")
#         print(f"{Colors.BOLD}{'PID':<8} {'PPID':<8} {'Name':<25} {'Memory(MB)':<12} {'CPU%':<8} {'User':<20} {'Status':<10}{Colors.ENDC}")
#         print(f"{Colors.HEADER}{'='*120}{Colors.ENDC}")
        
#         for proc in processes[:30]:  # Show top 30 processes
#             # Color based on suspicion
#             if self.is_suspicious_process(proc['name'], proc['cmdline']):
#                 name_color = Colors.FAIL
#                 status_color = Colors.FAIL
#             elif proc['memory_mb'] > 500:
#                 name_color = Colors.WARNING
#                 status_color = Colors.WARNING
#             else:
#                 name_color = Colors.CYAN
#                 status_color = Colors.DIM
            
#             # Truncate username if too long
#             username = proc['username'][:19] if len(proc['username']) > 19 else proc['username']
            
#             print(f"{proc['pid']:<8} {proc['ppid']:<8} "
#                   f"{name_color}{proc['name'][:24]:<25}{Colors.ENDC} "
#                   f"{proc['memory_mb']:<12.1f} "
#                   f"{proc['cpu_percent']:<8.1f} "
#                   f"{Colors.DIM}{username:<20}{Colors.ENDC} "
#                   f"{status_color}{proc['status']:<10}{Colors.ENDC}")
        
#         if len(processes) > 30:
#             print(f"{Colors.DIM}... and {len(processes)-30} more processes{Colors.ENDC}")
        
#         print(f"{Colors.HEADER}{'='*120}{Colors.ENDC}")
#         print(f"{Colors.OKGREEN}Total processes: {len(processes)}{Colors.ENDC}")
    
#     def print_network_table(self, connections):
#         """Print network connections in table format"""
#         print(f"\n{Colors.HEADER}{'='*100}{Colors.ENDC}")
#         print(f"{Colors.BOLD}{'Protocol':<8} {'Local Address':<25} {'Remote Address':<25} {'Status':<12} {'PID':<8} {'Process':<20}{Colors.ENDC}")
#         print(f"{Colors.HEADER}{'='*100}{Colors.ENDC}")
        
#         # Filter to show established connections and listeners
#         important_conns = [c for c in connections if c['status'] in ['ESTABLISHED', 'LISTEN']]
        
#         if not important_conns:
#             print(f"{Colors.DIM}No active network connections found{Colors.ENDC}")
#         else:
#             for conn in important_conns[:20]:
#                 # Color based on status
#                 if conn['status'] == 'ESTABLISHED':
#                     status_color = Colors.WARNING
#                 elif conn['status'] == 'LISTEN':
#                     status_color = Colors.OKGREEN
#                 else:
#                     status_color = Colors.DIM
                
#                 # Check for suspicious ports
#                 try:
#                     port = int(conn['local_addr'].split(':')[-1]) if conn['local_addr'] != '*:*' else 0
#                     if self.is_suspicious_port(port):
#                         protocol_color = Colors.FAIL
#                     else:
#                         protocol_color = Colors.OKBLUE
#                 except:
#                     protocol_color = Colors.DIM
                
#                 print(f"{protocol_color}{conn['protocol']:<8}{Colors.ENDC} "
#                       f"{Colors.DIM}{conn['local_addr'][:24]:<25}{Colors.ENDC} "
#                       f"{Colors.DIM}{conn['remote_addr'][:24]:<25}{Colors.ENDC} "
#                       f"{status_color}{conn['status']:<12}{Colors.ENDC} "
#                       f"{conn['pid']:<8} "
#                       f"{Colors.DIM}{conn['process'][:19]:<20}{Colors.ENDC}")
            
#             if len(important_conns) > 20:
#                 print(f"{Colors.DIM}... and {len(important_conns)-20} more connections{Colors.ENDC}")
        
#         print(f"{Colors.HEADER}{'='*100}{Colors.ENDC}")
#         print(f"{Colors.OKGREEN}Total connections: {len(connections)} (ESTABLISHED: {len([c for c in connections if c['status']=='ESTABLISHED'])}, LISTEN: {len([c for c in connections if c['status']=='LISTEN'])}){Colors.ENDC}")
    
#     def print_suspicious_table(self, suspicious):
#         """Print suspicious findings"""
#         if not suspicious:
#             print(f"\n{Colors.OKGREEN}[✓] No suspicious indicators found{Colors.ENDC}")
#             return
        
#         print(f"\n{Colors.FAIL}{'='*100}{Colors.ENDC}")
#         print(f"{Colors.FAIL}⚠️⚠️⚠️  SUSPICIOUS INDICATORS DETECTED!  ⚠️⚠️⚠️{Colors.ENDC}")
#         print(f"{Colors.FAIL}{'='*100}{Colors.ENDC}")
        
#         for item in suspicious:
#             print(f"\n{Colors.FAIL}[!] {item['type']}{Colors.ENDC}")
#             print(f"    Indicator: {Colors.WARNING}{item['indicator']}{Colors.ENDC}")
#             print(f"    Description: {Colors.DIM}{item['description']}{Colors.ENDC}")
            
#             if item['type'] == 'PROCESS':
#                 print(f"    PID: {item['pid']}")
#                 print(f"    Name: {item['name']}")
#                 if item['cmdline']:
#                     print(f"    Command: {item['cmdline'][:150]}...")
#             else:
#                 print(f"    Process: {item.get('process', 'N/A')}")
#                 print(f"    PID: {item.get('pid', 'N/A')}")
#                 if 'local_addr' in item:
#                     print(f"    Address: {item['local_addr']}")
#                 if 'remote_addr' in item:
#                     print(f"    Remote: {item['remote_addr']}")
        
#         print(f"\n{Colors.FAIL}{'='*100}{Colors.ENDC}")
#         print(f"{Colors.FAIL}Total suspicious indicators: {len(suspicious)}{Colors.ENDC}")
    
#     def save_json_report(self, processes, connections, suspicious, output_file):
#         """Save analysis results to JSON"""
#         report = {
#             'scan_info': {
#                 'timestamp': datetime.datetime.now().isoformat(),
#                 'hostname': socket.gethostname(),
#                 'system': f"{platform.system()} {platform.release()}",
#                 'total_processes': len(processes),
#                 'total_connections': len(connections),
#                 'suspicious_count': len(suspicious)
#             },
#             'processes': processes[:100],  # Top 100 processes
#             'network_connections': connections[:50],  # Top 50 connections
#             'suspicious_indicators': suspicious
#         }
        
#         try:
#             with open(output_file, 'w') as f:
#                 json.dump(report, f, indent=2)
#             print(f"\n{Colors.OKGREEN}[+] Report saved to {output_file}{Colors.ENDC}")
#         except Exception as e:
#             print(f"\n{Colors.FAIL}[-] Failed to save report: {e}{Colors.ENDC}")
    
#     def print_summary(self, processes, connections, suspicious):
#         """Print summary statistics"""
#         print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
#         print(f"{Colors.BOLD}  FORENSICS SUMMARY{Colors.ENDC}")
#         print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        
#         # Process statistics
#         total_memory = sum(p['memory_mb'] for p in processes)
#         total_cpu = sum(p['cpu_percent'] for p in processes)
        
#         print(f"\n{Colors.OKGREEN}Process Statistics:{Colors.ENDC}")
#         print(f"  Total processes: {len(processes)}")
#         print(f"  Total memory usage: {total_memory:.1f} MB ({total_memory/1024:.2f} GB)")
#         print(f"  Total CPU usage: {total_cpu:.1f}%")
        
#         # Top memory consumers
#         print(f"\n{Colors.OKGREEN}Top 5 Memory Consumers:{Colors.ENDC}")
#         for i, proc in enumerate(processes[:5], 1):
#             if self.is_suspicious_process(proc['name'], proc['cmdline']):
#                 color = Colors.FAIL
#             else:
#                 color = Colors.DIM
#             print(f"  {i}. {color}{proc['name']}{Colors.ENDC} - {proc['memory_mb']:.1f} MB")
        
#         # Network statistics
#         established = len([c for c in connections if c['status'] == 'ESTABLISHED'])
#         listening = len([c for c in connections if c['status'] == 'LISTEN'])
        
#         print(f"\n{Colors.OKGREEN}Network Statistics:{Colors.ENDC}")
#         print(f"  Total connections: {len(connections)}")
#         print(f"  Established: {established}")
#         print(f"  Listening: {listening}")
        
#         print(f"\n{Colors.OKGREEN}Suspicious Indicators:{Colors.ENDC}")
#         print(f"  Total: {len(suspicious)}")
        
#         for item in suspicious[:5]:
#             print(f"    • {item['indicator']} ({item['type']})")
        
#         print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
    
#     def print_defenses(self):
#         """Print defense mechanisms against memory forensics"""
#         print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
#         print(f"{Colors.BOLD}  DEFENSE AGAINST MEMORY FORENSICS{Colors.ENDC}")
#         print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        
#         defenses = [
#             ("Process Hiding (DKOM)", "Remove process from EPROCESS list"),
#             ("Code Injection", "Inject into legitimate processes"),
#             ("Rootkits", "Hook system calls, hide network connections"),
#             ("Anti-forensics", "Wipe memory, encrypt data before exit"),
#             ("Living off the land", "Use legitimate Windows/Linux tools"),
#             ("Packer/Crypters", "Obfuscate executable signatures"),
#             ("Reflective DLL Injection", "Load DLL from memory without disk write"),
#             ("Process Hollowing", "Replace legitimate process memory"),
#             ("Memory Encryption", "Encrypt sensitive data in memory"),
#             ("Fast Exit", "Delete artifacts before termination")
#         ]
        
#         for title, desc in defenses:
#             print(f"{Colors.OKGREEN}{title}{Colors.ENDC}: {Colors.DIM}{desc}{Colors.ENDC}")
        
#         print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")

# def main():
#     import argparse
    
#     parser = argparse.ArgumentParser(description="Memory Forensics Analyzer")
#     parser.add_argument("-o", "--output", help="Save JSON report to file")
#     parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
#     parser.add_argument("-t", "--tree", action="store_true", help="Show process tree")
    
#     args = parser.parse_args()
    
#     # Create analyzer
#     analyzer = MemoryForensicsAnalyzer(verbose=args.verbose)
    
#     # Display banner
#     analyzer.banner()
    
#     # Get data
#     print(f"{Colors.OKBLUE}[*] Analyzing processes...{Colors.ENDC}")
#     processes = analyzer.get_all_processes()
    
#     print(f"{Colors.OKBLUE}[*] Analyzing network connections...{Colors.ENDC}")
#     connections = analyzer.get_network_connections()
    
#     print(f"{Colors.OKBLUE}[*] Detecting suspicious indicators...{Colors.ENDC}")
#     suspicious = analyzer.analyze_suspicious_indicators(processes, connections)
    
#     # Display results
#     analyzer.print_processes_table(processes)
    
#     if args.tree:
#         print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
#         print(f"{Colors.BOLD}  PROCESS TREE VISUALIZATION{Colors.ENDC}")
#         print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
#         tree = analyzer.build_process_tree(processes)
#         analyzer.print_process_tree(tree)
    
#     analyzer.print_network_table(connections)
#     analyzer.print_suspicious_table(suspicious)
#     analyzer.print_summary(processes, connections, suspicious)
    
#     # Save JSON report
#     if args.output:
#         analyzer.save_json_report(processes, connections, suspicious, args.output)
    
#     # Print defense documentation
#     if args.verbose:
#         analyzer.print_defenses()

# if __name__ == "__main__":
#     main()