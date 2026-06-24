#!/usr/bin/env python3
"""
PROJECT #34 — IoT Scanner — UPnP/SSDP Discovery
"""

import os
import sys
import socket
import time
import threading
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

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

class UPnPScanner:
    def __init__(self, timeout=10, output_file="upnp_report.html"):
        self.timeout = timeout
        self.output_file = output_file
        self.devices = []
        self.lock = threading.Lock()
        
    def banner(self):
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}  PROJECT #34 — IoT Scanner — UPnP/SSDP Discovery{Colors.ENDC}")
        print(f"{Colors.OKBLUE}  Discovering UPnP devices and detecting security issues{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        print(f"{Colors.RED}⚠️⚠️⚠️  ETHICAL WARNING  ⚠️⚠️⚠️{Colors.ENDC}")
        print(f"{Colors.YELLOW}Only scan networks you own or have permission to test.{Colors.ENDC}\n")
    
    def discover_devices(self):
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
                        print(f"{Colors.OKGREEN}[+] Found device at {addr[0]}{Colors.ENDC}")
                        
                except socket.timeout:
                    break
                except:
                    pass
            
            sock.close()
            print(f"{Colors.OKGREEN}[+] Found {len(responses)} devices{Colors.ENDC}")
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
                device['serial_number'] = device_elem.findtext('serialNumber', 'Unknown')
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
                'description': 'UPnP port 1900 is open and responding',
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
                        'description': 'MediaServer service exposed - may expose media content',
                        'recommendation': 'Restrict MediaServer access to trusted devices'
                    })
                    break
        
        if device_desc and 'manufacturer' in device_desc:
            default_cred_devices = ['TP-Link', 'D-Link', 'Netgear', 'Linksys', 'Belkin', 'Asus']
            for brand in default_cred_devices:
                if brand in device_desc.get('manufacturer', ''):
                    issues.append({
                        'severity': 'HIGH',
                        'type': 'DEFAULT_CREDENTIALS',
                        'description': f'Device uses default credentials ({brand} may have default admin/admin)',
                        'recommendation': 'Change default credentials immediately'
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
        self.banner()
        
        if not REQUESTS_AVAILABLE:
            print(f"{Colors.FAIL}[-] requests not available{Colors.ENDC}")
            return
        
        discovered = self.discover_devices()
        
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
    <title>UPnP Security Scanner Report</title>
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
        <h1>🔍 UPnP Security Scanner Report</h1>
        <p class="warning">⚠️ EDUCATIONAL USE ONLY ⚠️</p>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Devices Found: {len(self.devices)}</p>
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
            html += '<p style="color:#888;">No UPnP devices found.</p>'
        else:
            for device in self.devices:
                info = device.get('device_info', {})
                issues = device.get('issues', [])
                
                html += f"""
        <div class="device">
            <div class="ip">📡 {device['ip']}:{device['port']}</div>
            <div>Name: {info.get('friendly_name', 'Unknown')}</div>
            <div>Manufacturer: {info.get('manufacturer', 'Unknown')}</div>"""
                
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
        <p>Generated by UPnP Scanner | 100 Ethical Hacking Projects</p>
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
    
    parser = argparse.ArgumentParser(description="UPnP Security Scanner")
    parser.add_argument("--timeout", type=int, default=10, help="Scan timeout in seconds")
    parser.add_argument("--output", default="upnp_report.html", help="HTML report file")
    
    args = parser.parse_args()
    
    scanner = UPnPScanner(timeout=args.timeout, output_file=args.output)
    scanner.run_scan()

if __name__ == "__main__":
    main()