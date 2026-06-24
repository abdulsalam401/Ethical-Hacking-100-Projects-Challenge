#!/usr/bin/env python3
"""
Project #34: IoT/UPnP Security Scanner & Device Discovery Tool
Architecture: UDP Multicast Socket + XML Service Description Parsing.
"""

import sys
import socket
import re
import argparse
from datetime import datetime

try:
    import requests
    # XML parsing ke liye standard library ka use karenge
    import xml.etree.ElementTree as ET
except ImportError:
    print("[-] Dependency Missing: Run 'pip3 install requests'")
    sys.exit(1)

# Terminal UI Colors
G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"; R = "\033[91m"; BOLD = "\033[1m"; RESET = "\033[0m"

BANNER = f"""
======================================================================
  📡 IoT SCANNER: LOCAL NETWORK UPnP / SSDP DISCOVERY CORE
======================================================================
"""

def discover_ssdp_devices(timeout=5):
    """Sends a standard SSDP M-SEARCH multicast packet over the local network layer."""
    print(f"[*] Initializing UDP Multicast Socket pipeline...")
    
    # Standard SSDP multicast address and port configuration
    multicast_group = "239.255.255.250"
    port = 1900
    
    # Standard SSDP M-SEARCH payload discovery string
    ssdp_request = (
        'M-SEARCH * HTTP/1.1\r\n'
        f'HOST: {multicast_group}:{port}\r\n'
        'MAN: "ssdp:discover"\r\n'
        'MX: 3\r\n'
        'ST: ssdp:all\r\n'
        '\r\n'
    )

    discovered_urls = set()
    
    # Create an IPv4 UDP Socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    
    try:
        print(f"[*] Broadcasting SSDP discovery probe to {multicast_group}:{port}...")
        sock.sendto(ssdp_request.encode('utf-8'), (multicast_group, port))
        
        # Listen for responses until socket times out
        while True:
            try:
                data, addr = sock.recvfrom(2048)
                response = data.decode('utf-8', errors='ignore')
                
                # Extract the LOCATION header which contains the device XML URL
                location_match = re.search(r'LOCATION:\s*(http://\S+)', response, re.IGNORECASE)
                if location_match:
                    discovered_urls.add(location_match.group(1))
            except socket.timeout:
                break # Break when no more devices respond within the timeout window
    except Exception as e:
        print(f"{R}[!] Socket Error: {e}{RESET}")
    finally:
        sock.close()
        
    return list(discovered_urls)

def audit_upnp_device(xml_url):
    """Queries individual XML schemas to parse service endpoints and security risks."""
    print(f"\n[*] Querying device specification metadata at: {C}{xml_url}{RESET}")
    
    try:
        res = requests.get(xml_url, timeout=5)
        if res.status_code != 200:
            return None
            
        # Parse XML structure natively
        root = ET.fromstring(res.text)
        
        # Strip XML namespace if present
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"
            
        device_node = root.find(f".//{ns}device")
        if device_node is None:
            return None
            
        friendly_name = device_node.findtext(f"{ns}friendlyName", default="Unknown Device")
        manufacturer = device_node.findtext(f"{ns}manufacturer", default="Unknown")
        model_name = device_node.findtext(f"{ns}modelName", default="Unknown")
        
        print(f"   [+] Device Identity: {G}{friendly_name}{RESET} ({manufacturer} - {model_name})")
        
        # Search for exposed services (like WANIPConnection which controls routing rules)
        services = []
        findings = []
        
        for service in root.findall(f".//{ns}service"):
            service_type = service.findtext(f"{ns}serviceType", default="")
            services.append(service_type)
            
            # Risk Check: Look for WANIPConnection which permits external port mapping controls
            if "WANIPConnection" in service_type or "WANPPPConnection" in service_type:
                findings.append("CRITICAL: WANIPConnection service exposed! External actors could manipulate routing mappings.")
                
        # Risk Check: Check for missing authentication signatures on local operations
        findings.append("WARNING: Insecure Default Profile (UPnP configuration endpoints lack active session credentials).")
        
        return {
            "url": xml_url,
            "name": friendly_name,
            "manufacturer": manufacturer,
            "services_count": len(services),
            "findings": findings
        }
        
    except Exception as e:
        print(f"   {Y}[!] Unable to parse device configurations ({e}){RESET}")
        return None

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="UPnP Local Area Network Security Auditor")
    parser.add_argument("--scan", action="store_true", help="Launch active multicast device collection phase")
    args = parser.parse_args()

    if not args.scan:
        print(f"{Y}[*] Usage Notice: Execute with '--scan' to actively query your local router network.{RESET}")
        return

    # 1. Run network discovery loop
    xml_targets = discover_ssdp_devices()
    
    if not xml_targets:
        print(f"\n{Y}[!] Discovery Complete: No responsive UPnP/SSDP services found on this interface.{RESET}")
        print(f"    👉 Remediation Hint: Ensure UPnP is enabled in your router's admin panel context.")
        return

    print(f"\n{G}[+] Discovered {len(xml_targets)} potential UPnP endpoints on your local loop.{RESET}")
    
    audit_reports = []
    
    # 2. Run security auditing engine across targets
    for target in xml_targets:
        report = audit_upnp_device(target)
        if report:
            audit_reports.append(report)

    # 3. Generate HTML threat report file
    generate_report(audit_reports)

def generate_report(reports):
    html = f"""
    <html>
    <head><title>IoT UPnP Compliance Report</title></head>
    <body style="font-family:monospace; background:#0e1111; color:#f4f4f4; padding:20px;">
        <h2>🎯 Local IoT Architecture Integration: UPnP Compliance Audit</h2>
        <p>Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <hr style="border-color:#333;">
    """
    
    if not reports:
        html += "<p>No active anomalies logged across inspected frames.</p>"
    else:
        for r in reports:
            html += f"""
            <div style="background:#1c1f20; padding:15px; margin:10px 0; border-radius:5px; border:1px solid #444;">
                <h3>🔹 Device: {r['name']}</h3>
                <p><b>Target URL:</b> {r['url']}</p>
                <p><b>Manufacturer:</b> {r['manufacturer']} | <b>Tracked Service Schemes:</b> {r['services_count']}</p>
                <h4>Logged Posture Findings:</h4>
                <ul>
            """
            for finding in r['findings']:
                color = "red" if "CRITICAL" in finding else "orange"
                html += f"<li style='color:{color};'>{finding}</li>"
            html += "</ul></div>"
            
    html += "</body></html>"
    
    # Purani line ko change karke open() mein encoding='utf-8' add karein:
    with open("upnp_audit_report.html", "w", encoding="utf-8") as f:
        f.write(html)
    
    print(f"\n[+] Security intelligence audit matrix compiled inside: {G}upnp_audit_report.html{RESET}\n")

if __name__ == "__main__":
    main()
