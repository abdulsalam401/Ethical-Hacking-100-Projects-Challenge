#!/usr/bin/env python3
"""
PROJECT #34 — Enhanced IoT Scanner — UPnP/SSDP Discovery + Network Scan
"""

import os
import sys
import socket
import time
import threading
import xml.etree.ElementTree as ET
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import ipaddress

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[-] requests not installed. Run: pip install requests")

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
    CYAN = Fore.CYAN + Style.BRIGHT

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
SSDP_MSG = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 3\r\n"
    "ST: upnp:rootdevice\r\n\r\n"
)

class EnhancedUPnPScanner:
    def __init__(self, timeout=10, output_file="upnp_report.html", network_scan=True):
        self.timeout = timeout
        self.output_file = output_file
        self.network_scan = network_scan
        self.devices = []
        self.lock = threading.Lock()
        self.all_ips = set()
        
    def get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "192.168.1.1"
    
    def get_network_range(self):
        """Get network range from local IP"""
        ip = self.get_local_ip()
        # Assume /24 network
        base = '.'.join(ip.split('.')[:-1])
        return f"{base}.0/24"
    
    def ping_host(self, ip):
        """Ping a host to check if alive"""
        try:
            # Use ping command
            param = '-n' if sys.platform.startswith('win') else '-c'
            cmd = ['ping', param, '1', '-W', '1', ip]
            result = subprocess.run(cmd, capture_output=True, timeout=2)
            return result.returncode == 0
        except:
            return False
    
    def scan_network(self):
        """Scan network for live hosts"""
        print(f"{Colors.OKBLUE}[*] Scanning network for live hosts...{Colors.ENDC}")
        
        network = self.get_network_range()
        print(f"{Colors.DIM}[*] Network: {network}{Colors.ENDC}")
        
        live_hosts = []
        base_ip = network.split('/')[0].rsplit('.', 1)[0]
        
        # Scan common IPs first (gateway, common devices)
        common_ips = [f"{base_ip}.1", f"{base_ip}.254", f"{base_ip}.100", f"{base_ip}.50"]
        for ip in common_ips:
            if self.ping_host(ip):
                live_hosts.append(ip)
                print(f"{Colors.OKGREEN}[+] Live host: {ip}{Colors.ENDC}")
        
        # Scan range 2-50 for faster scanning
        print(f"{Colors.DIM}[*] Scanning range {base_ip}.2-{base_ip}.50{Colors.ENDC}")
        for i in range(2, 51):
            ip = f"{base_ip}.{i}"
            if ip not in live_hosts and self.ping_host(ip):
                live_hosts.append(ip)
                print(f"{Colors.OKGREEN}[+] Live host: {ip}{Colors.ENDC}")
        
        print(f"{Colors.OKGREEN}[+] Found {len(live_hosts)} live hosts{Colors.ENDC}")
        return live_hosts
    
    def discover_devices(self):
        """Discover UPnP devices via SSDP"""
        print(f"{Colors.OKBLUE}[*] Discovering UPnP devices via SSDP...{Colors.ENDC}")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(self.timeout)
            
            sock.sendto(SSDP_MSG.encode(), (SSDP_ADDR, SSDP_PORT))
            print(f"{Colors.DIM}[*] Sent SSDP discovery request{Colors.ENDC}")
            
            responses = []
            start_time = time.time()
            
            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    response = data.decode('utf-8', errors='ignore')
                    
                    location = None
                    for line in response.split('\r\n'):
                        if line.lower().startswith('location:'):
                            location = line.split(':', 1)[1].strip()
                            break
                    
                    if location:
                        responses.append({
                            'ip': addr[0],
                            'port': addr[1],
                            'location': location
                        })
                        self.all_ips.add(addr[0])
                        print(f"{Colors.OKGREEN}[+] Found device at {addr[0]}{Colors.ENDC}")
                        
                except socket.timeout:
                    break
                except:
                    pass
            
            sock.close()
            print(f"{Colors.OKGREEN}[+] Found {len(responses)} UPnP devices{Colors.ENDC}")
            return responses
            
        except Exception as e:
            print(f"{Colors.FAIL}[-] Error: {e}{Colors.ENDC}")
            return []
    
    def parse_device_description(self, location):
        try:
            if not REQUESTS_AVAILABLE:
                return None
            
            response = requests.get(location, timeout=5)
            if response.status_code != 200:
                return None
            
            root = ET.fromstring(response.text)
            device = {}
            
            device_elem = root.find('.//device')
            if device_elem is not None:
                device['friendly_name'] = device_elem.findtext('friendlyName', 'Unknown')
                device['manufacturer'] = device_elem.findtext('manufacturer', 'Unknown')
                device['model_name'] = device_elem.findtext('modelName', 'Unknown')
                device['model_number'] = device_elem.findtext('modelNumber', 'Unknown')
                device['udn'] = device_elem.findtext('UDN', 'Unknown')
                
                services = []
                service_list = device_elem.find('.//serviceList')
                if service_list is not None:
                    for service in service_list.findall('service'):
                        services.append({
                            'type': service.findtext('serviceType', ''),
                            'id': service.findtext('serviceId', ''),
                            'control_url': service.findtext('controlURL', '')
                        })
                device['services'] = services
            
            return device
            
        except Exception as e:
            print(f"{Colors.FAIL}[-] Error parsing: {e}{Colors.ENDC}")
            return None
    
    def check_security_issues(self, device_info, device_desc):
        issues = []
        
        if device_info.get('port') == 1900:
            issues.append({
                'severity': 'MEDIUM',
                'type': 'UPnP_PORT_OPEN',
                'description': 'UPnP port 1900 is open',
                'recommendation': 'Disable UPnP if not needed'
            })
        
        if device_desc and 'services' in device_desc:
            for service in device_desc['services']:
                if 'WANIPConnection' in service.get('type', ''):
                    issues.append({
                        'severity': 'HIGH',
                        'type': 'WANIPCONNECTION_EXPOSED',
                        'description': 'WANIPConnection service exposed - allows external port mapping',
                        'recommendation': 'Disable UPnP or restrict WANIPConnection access'
                    })
                    break
            
            for service in device_desc['services']:
                if 'MediaServer' in service.get('type', ''):
                    issues.append({
                        'severity': 'LOW',
                        'type': 'MEDIASERVER_EXPOSED',
                        'description': 'MediaServer service exposed',
                        'recommendation': 'Restrict MediaServer access'
                    })
                    break
        
        return issues
    
    def scan_device(self, device_info):
        ip = device_info['ip']
        location = device_info['location']
        
        print(f"\n{Colors.OKBLUE}[*] Scanning device: {ip}{Colors.ENDC}")
        
        device_desc = self.parse_device_description(location)
        
        if device_desc:
            print(f"{Colors.OKGREEN}[+] Device: {device_desc.get('friendly_name', 'Unknown')}{Colors.ENDC}")
            print(f"{Colors.DIM}[+] Manufacturer: {device_desc.get('manufacturer', 'Unknown')}{Colors.ENDC}")
            print(f"{Colors.DIM}[+] Model: {device_desc.get('model_name', 'Unknown')}{Colors.ENDC}")
        
        issues = self.check_security_issues(device_info, device_desc)
        
        if issues:
            print(f"{Colors.WARNING}[!] Found {len(issues)} issues:{Colors.ENDC}")
            for issue in issues:
                color = Colors.FAIL if issue['severity'] == 'HIGH' else Colors.WARNING
                print(f"{color}    - {issue['type']}: {issue['description']}{Colors.ENDC}")
        
        result = {
            'ip': ip,
            'port': device_info['port'],
            'location': location,
            'device_info': device_desc,
            'issues': issues,
            'scan_time': datetime.now().isoformat()
        }
        
        with self.lock:
            self.devices.append(result)
        
        return result
    
    def run_scan(self):
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}  PROJECT #34 — Enhanced IoT Scanner{Colors.ENDC}")
        print(f"{Colors.OKBLUE}  UPnP Discovery + Network Scan{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        print(f"{Colors.RED}⚠️⚠️⚠️  ETHICAL WARNING  ⚠️⚠️⚠️{Colors.ENDC}")
        print(f"{Colors.YELLOW}Only scan networks you own.{Colors.ENDC}\n")
        
        if not REQUESTS_AVAILABLE:
            print(f"{Colors.FAIL}[-] requests not available{Colors.ENDC}")
            return
        
        # First, discover UPnP devices
        discovered = self.discover_devices()
        
        # Then scan network for live hosts
        if self.network_scan:
            live_hosts = self.scan_network()
            for ip in live_hosts:
                if ip not in self.all_ips:
                    # Check if any UPnP service is running on this host
                    # Add a basic check for port 1900
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, 1900))
                    sock.close()
                    if result == 0:
                        print(f"{Colors.OKGREEN}[+] Found UPnP service on {ip}:1900{Colors.ENDC}")
                        self.all_ips.add(ip)
                        # Try to discover on this IP
                        try:
                            sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                            sock2.settimeout(2)
                            sock2.sendto(SSDP_MSG.encode(), (ip, 1900))
                            data, addr = sock2.recvfrom(1024)
                            sock2.close()
                            # Parse response to get location
                            response = data.decode('utf-8', errors='ignore')
                            location = None
                            for line in response.split('\r\n'):
                                if line.lower().startswith('location:'):
                                    location = line.split(':', 1)[1].strip()
                                    break
                            if location:
                                discovered.append({
                                    'ip': ip,
                                    'port': 1900,
                                    'location': location
                                })
                                print(f"{Colors.OKGREEN}[+] Found UPnP device at {ip}{Colors.ENDC}")
                        except:
                            pass
        
        if not discovered:
            print(f"{Colors.WARNING}[!] No UPnP devices found.{Colors.ENDC}")
            self.generate_report()
            return
        
        print(f"\n{Colors.OKBLUE}[*] Scanning {len(discovered)} devices...{Colors.ENDC}")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.scan_device, device): device for device in discovered}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"{Colors.FAIL}[-] Error: {e}{Colors.ENDC}")
        
        self.generate_report()
    
    def generate_report(self):
        print(f"\n{Colors.OKBLUE}[*] Generating HTML report...{Colors.ENDC}")
        
        high_count = 0
        medium_count = 0
        low_count = 0
        for device in self.devices:
            for issue in device.get('issues', []):
                if issue['severity'] == 'HIGH':
                    high_count += 1
                elif issue['severity'] == 'MEDIUM':
                    medium_count += 1
                else:
                    low_count += 1
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>IoT Security Scanner Report</title>
    <style>
        body {{font-family:'Segoe UI',sans-serif;background:#1a1a2e;color:#e0e0e0;padding:20px;}}
        .container {{max-width:1200px;margin:0 auto;}}
        .header {{background:linear-gradient(135deg,#16213e,#0f3460);padding:30px;border-radius:10px;margin-bottom:20px;}}
        .header h1 {{color:#00d4ff;}}
        .header .warning {{color:#ff4444;font-weight:bold;}}
        .stats {{display:flex;gap:20px;margin:20px 0;flex-wrap:wrap;}}
        .stat-box {{flex:1;min-width:120px;padding:20px;border-radius:8px;text-align:center;}}
        .stat-total {{background:#1a1a3e;}}
        .stat-high {{background:#ff0040;}}
        .stat-medium {{background:#ffa500;}}
        .stat-low {{background:#4a90d9;}}
        .stat-box .number {{font-size:32px;font-weight:bold;}}
        .stat-box .label {{font-size:12px;color:#888;}}
        .device {{background:#2d2d44;padding:15px;margin:10px 0;border-radius:8px;border-left:4px solid #00d4ff;}}
        .device .ip {{color:#00d4ff;font-weight:bold;font-size:16px;}}
        .issue {{padding:8px;margin:3px 0;border-radius:4px;font-size:12px;}}
        .issue.high {{background:#3d1a2e;border-left:3px solid #ff0040;}}
        .issue.medium {{background:#3d2a1a;border-left:3px solid #ffa500;}}
        .issue.low {{background:#1a2a3d;border-left:3px solid #4a90d9;}}
        .defense {{background:#0f3460;padding:15px;border-radius:8px;margin-top:20px;}}
        .defense h3 {{color:#00d4ff;}}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🔍 IoT Security Scanner Report</h1>
        <p class="warning">⚠️ EDUCATIONAL USE ONLY ⚠️</p>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Devices Found: {len(self.devices)}</p>
        <p>Network IPs Detected: {len(self.all_ips)}</p>
    </div>
    
    <div class="stats">
        <div class="stat-box stat-total"><div class="number">{len(self.devices)}</div><div class="label">Devices</div></div>
        <div class="stat-box stat-high"><div class="number">{high_count}</div><div class="label">High</div></div>
        <div class="stat-box stat-medium"><div class="number">{medium_count}</div><div class="label">Medium</div></div>
        <div class="stat-box stat-low"><div class="number">{low_count}</div><div class="label">Low</div></div>
    </div>
    
    <div style="margin:20px 0;">
        <h2 style="color:#00d4ff;">📋 Discovered Devices</h2>"""
        
        if not self.devices:
            html += '<p style="color:#888;">No devices found.</p>'
        else:
            for device in self.devices:
                info = device.get('device_info', {})
                issues = device.get('issues', [])
                
                html += f"""
        <div class="device">
            <div class="ip">📡 {device['ip']}:{device['port']}</div>
            <div>Name: {info.get('friendly_name', 'Unknown')}</div>
            <div>Manufacturer: {info.get('manufacturer', 'Unknown')}</div>
            <div>Model: {info.get('model_name', 'Unknown')}</div>"""
                
                if issues:
                    html += '<div style="margin-top:5px;"><strong style="color:#ffa500;">Issues:</strong>'
                    for issue in issues:
                        sev_class = issue['severity'].lower()
                        html += f"""
                    <div class="issue {sev_class}">
                        [{issue['severity']}] {issue['type']} - {issue['description']}
                        <br><span style="color:#888;font-size:11px;">→ {issue['recommendation']}</span>
                    </div>"""
                    html += '</div>'
                
                html += '</div>'
        
        html += """
    </div>
    
    <div class="defense">
        <h3>🛡️ Defenses Against UPnP Attacks</h3>
        <table style="width:100%;border-collapse:collapse;">
            <tr><th style="text-align:left;color:#00d4ff;">Defense</th><th style="text-align:left;color:#00d4ff;">Description</th></tr>
            <tr><td>Disable UPnP</td><td>If not needed, disable UPnP on all devices</td></tr>
            <tr><td>Use UPnP with Authentication</td><td>Enable authentication if available</td></tr>
            <tr><td>Segment IoT Devices</td><td>Place IoT devices on separate VLAN</td></tr>
            <tr><td>Monitor UPnP Traffic</td><td>Monitor for unusual UPnP activity</td></tr>
            <tr><td>Keep Firmware Updated</td><td>Regularly update device firmware</td></tr>
        </table>
    </div>
    
    <div style="text-align:center;color:#666;margin-top:30px;font-size:12px;">
        <p>Generated by IoT Scanner | 100 Ethical Hacking Projects</p>
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
    
    parser = argparse.ArgumentParser(description="Enhanced IoT Security Scanner")
    parser.add_argument("--timeout", type=int, default=10, help="Scan timeout in seconds")
    parser.add_argument("--output", default="upnp_report.html", help="HTML report file")
    parser.add_argument("--no-network-scan", action="store_true", help="Skip network scan")
    
    args = parser.parse_args()
    
    scanner = EnhancedUPnPScanner(
        timeout=args.timeout, 
        output_file=args.output,
        network_scan=not args.no_network_scan
    )
    scanner.run_scan()

if __name__ == "__main__":
    main()