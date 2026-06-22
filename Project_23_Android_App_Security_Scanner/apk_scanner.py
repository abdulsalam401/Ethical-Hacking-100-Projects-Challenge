#!/usr/bin/env python3
"""
==============================================================
  PROJECT #23 — Android App Security Scanner (Static Analysis)
  Scans APK files for security vulnerabilities
==============================================================
"""

import os
import sys
import re
import json
import subprocess
import tempfile
import shutil
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from colorama import init, Fore, Style

init(autoreset=True)

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

# YARA-style rules for string scanning
STRING_RULES = {
    "api_key": {
        "patterns": [
            r'[A-Za-z0-9_\-]{32,64}',
            r'AIza[0-9A-Za-z-_]{35}',
            r'sk_live_[0-9a-zA-Z]{24}',
            r'pk_live_[0-9a-zA-Z]{24}',
            r'key[=:]["\']?[A-Za-z0-9_\-]{20,50}["\']?',
            r'api_key[=:]["\']?[A-Za-z0-9_\-]{20,50}["\']?',
            r'token[=:]["\']?[A-Za-z0-9_\-]{20,50}["\']?',
            r'secret[=:]["\']?[A-Za-z0-9_\-]{20,50}["\']?'
        ],
        "severity": "HIGH",
        "description": "Hardcoded API key or secret detected"
    },
    "password": {
        "patterns": [
            r'password[=:]["\']?[A-Za-z0-9!@#$%^&*()_+]{6,30}["\']?',
            r'passwd[=:]["\']?[A-Za-z0-9!@#$%^&*()_+]{6,30}["\']?',
            r'pwd[=:]["\']?[A-Za-z0-9!@#$%^&*()_+]{6,30}["\']?'
        ],
        "severity": "HIGH",
        "description": "Hardcoded password detected"
    }
}

# Dangerous permissions with severity
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": {"severity": "HIGH", "description": "Read SMS messages"},
    "android.permission.SEND_SMS": {"severity": "HIGH", "description": "Send SMS messages"},
    "android.permission.READ_PHONE_STATE": {"severity": "HIGH", "description": "Read phone state"},
    "android.permission.PROCESS_OUTGOING_CALLS": {"severity": "HIGH", "description": "Process outgoing calls"},
    "android.permission.CAMERA": {"severity": "MEDIUM", "description": "Access camera"},
    "android.permission.RECORD_AUDIO": {"severity": "MEDIUM", "description": "Record audio"},
    "android.permission.READ_CONTACTS": {"severity": "MEDIUM", "description": "Read contacts"},
    "android.permission.ACCESS_FINE_LOCATION": {"severity": "MEDIUM", "description": "Fine location"},
    "android.permission.ACCESS_COARSE_LOCATION": {"severity": "MEDIUM", "description": "Coarse location"},
    "android.permission.READ_EXTERNAL_STORAGE": {"severity": "LOW", "description": "Read external storage"},
    "android.permission.WRITE_EXTERNAL_STORAGE": {"severity": "LOW", "description": "Write external storage"},
}

class APKScanner:
    def __init__(self, apk_path, output_file=None, verbose=False):
        self.apk_path = apk_path
        self.output_file = output_file or "scan_report.html"
        self.verbose = verbose
        self.issues = []
        self.decompile_dir = None
        self.manifest_path = None
        
    def banner(self):
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}  PROJECT #23 — Android App Security Scanner{Colors.ENDC}")
        print(f"{Colors.OKBLUE}  Static Analysis of Android APK Files{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        print(f"{Colors.OKGREEN}[+] APK: {self.apk_path}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Output: {self.output_file}{Colors.ENDC}\n")
    
    def decompile_apk(self):
        print(f"{Colors.OKBLUE}[*] Decompiling APK...{Colors.ENDC}")
        self.decompile_dir = tempfile.mkdtemp(prefix='apk_scan_')
        
        try:
            cmd = ['apktool', 'd', '-f', '-o', self.decompile_dir, self.apk_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"{Colors.FAIL}[-] Decompile failed{Colors.ENDC}")
                return False
            
            self.manifest_path = os.path.join(self.decompile_dir, 'AndroidManifest.xml')
            print(f"{Colors.OKGREEN}[+] Decompiled successfully{Colors.ENDC}")
            return True
            
        except Exception as e:
            print(f"{Colors.FAIL}[-] Decompile error: {e}{Colors.ENDC}")
            return False
    
    def parse_manifest(self):
        print(f"{Colors.OKBLUE}[*] Analyzing manifest...{Colors.ENDC}")
        
        if not self.manifest_path or not os.path.exists(self.manifest_path):
            print(f"{Colors.WARNING}[!] Manifest not found{Colors.ENDC}")
            return
        
        try:
            tree = ET.parse(self.manifest_path)
            root = tree.getroot()
            
            # Check allowBackup
            allow_backup = root.get('android:allowBackup')
            if allow_backup and allow_backup.lower() == 'true':
                self.issues.append({
                    'type': 'INSECURE_SETTING',
                    'severity': 'MEDIUM',
                    'description': 'allowBackup=true - App data can be backed up',
                    'location': 'AndroidManifest.xml',
                    'details': 'android:allowBackup="true"'
                })
            
            # Check usesCleartextTraffic
            cleartext = root.get('android:usesCleartextTraffic')
            if cleartext and cleartext.lower() == 'true':
                self.issues.append({
                    'type': 'INSECURE_SETTING',
                    'severity': 'HIGH',
                    'description': 'usesCleartextTraffic=true - App allows plaintext network traffic',
                    'location': 'AndroidManifest.xml',
                    'details': 'android:usesCleartextTraffic="true"'
                })
            
            # Check debuggable
            debug = root.get('android:debuggable')
            if debug and debug.lower() == 'true':
                self.issues.append({
                    'type': 'INSECURE_SETTING',
                    'severity': 'HIGH',
                    'description': 'android:debuggable=true - App is debuggable',
                    'location': 'AndroidManifest.xml',
                    'details': 'android:debuggable="true"'
                })
            
            # Check permissions
            for perm in root.findall('.//uses-permission'):
                perm_name = perm.get('android:name')
                if perm_name and perm_name in DANGEROUS_PERMISSIONS:
                    info = DANGEROUS_PERMISSIONS[perm_name]
                    self.issues.append({
                        'type': 'DANGEROUS_PERMISSION',
                        'severity': info['severity'],
                        'description': info['description'],
                        'location': 'AndroidManifest.xml',
                        'details': perm_name
                    })
            
            # Check exported components
            for component in root.findall('.//activity') + root.findall('.//service') + root.findall('.//receiver'):
                exported = component.get('android:exported')
                comp_name = component.get('android:name', 'Unknown')
                if exported and exported.lower() == 'true':
                    comp_type = 'Activity' if component.tag == 'activity' else ('Service' if component.tag == 'service' else 'Receiver')
                    self.issues.append({
                        'type': 'EXPORTED_COMPONENT',
                        'severity': 'MEDIUM',
                        'description': f'Exported {comp_type} accessible by other apps',
                        'location': 'AndroidManifest.xml',
                        'details': f'{comp_type}: {comp_name}'
                    })
            
            print(f"{Colors.OKGREEN}[+] Manifest analysis complete{Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.FAIL}[-] Manifest parse error: {e}{Colors.ENDC}")
    
    def scan_webview(self):
        print(f"{Colors.OKBLUE}[*] Scanning for WebView vulnerabilities...{Colors.ENDC}")
        
        webview_patterns = [
            (r'setJavaScriptEnabled\(\s*true\s*\)', 'MEDIUM', 'WebView with JavaScript enabled (XSS risk)'),
            (r'addJavascriptInterface\(', 'HIGH', 'JavaScript interface exposed (RCE risk)'),
            (r'setAllowUniversalAccessFromFileURLs\(\s*true\s*\)', 'HIGH', 'File URL access enabled'),
            (r'loadUrl\(\s*["\'][^"\']*["\']', 'LOW', 'WebView URL loading - check for dynamic URLs')
        ]
        
        if not self.decompile_dir:
            return
        
        try:
            for root, dirs, files in os.walk(self.decompile_dir):
                for file in files:
                    if file.endswith(('.smali', '.java', '.xml')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                for pattern, severity, desc in webview_patterns:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        self.issues.append({
                                            'type': 'WEBVIEW_VULNERABILITY',
                                            'severity': severity,
                                            'description': desc,
                                            'location': file_path.replace(self.decompile_dir, ''),
                                            'details': pattern
                                        })
                        except:
                            pass
            
            print(f"{Colors.OKGREEN}[+] WebView scan complete{Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.FAIL}[-] WebView scan error: {e}{Colors.ENDC}")
    
    def scan_strings(self):
        print(f"{Colors.OKBLUE}[*] Scanning for hardcoded secrets...{Colors.ENDC}")
        
        if not self.decompile_dir:
            return
        
        try:
            for root, dirs, files in os.walk(self.decompile_dir):
                for file in files:
                    if file.endswith(('.smali', '.xml', '.json', '.txt')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                for rule_name, rule in STRING_RULES.items():
                                    for pattern in rule['patterns']:
                                        matches = re.finditer(pattern, content, re.IGNORECASE)
                                        for match in matches:
                                            self.issues.append({
                                                'type': 'HARDCODED_SECRET',
                                                'severity': rule['severity'],
                                                'description': rule['description'],
                                                'location': file_path.replace(self.decompile_dir, ''),
                                                'details': match.group()
                                            })
                                            break
                        except:
                            pass
            
            print(f"{Colors.OKGREEN}[+] String scan complete{Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.FAIL}[-] String scan error: {e}{Colors.ENDC}")
    
    def generate_html_report(self):
        print(f"{Colors.OKBLUE}[*] Generating HTML report...{Colors.ENDC}")
        
        high = [i for i in self.issues if i['severity'] == 'HIGH']
        medium = [i for i in self.issues if i['severity'] == 'MEDIUM']
        low = [i for i in self.issues if i['severity'] == 'LOW']
        
        html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>APK Security Scan Report</title>
<style>
body {{font-family:'Segoe UI',sans-serif;background:#1a1a2e;color:#e0e0e0;padding:20px;}}
.container {{max-width:1200px;margin:0 auto;}}
.header {{background:linear-gradient(135deg,#16213e,#0f3460);padding:30px;border-radius:10px;margin-bottom:20px;}}
.header h1 {{color:#00d4ff;}}
.stats {{display:flex;gap:20px;margin:20px 0;flex-wrap:wrap;}}
.stat-box {{flex:1;min-width:120px;padding:20px;border-radius:8px;text-align:center;}}
.stat-high {{background:#ff0040;}}
.stat-medium {{background:#ffa500;}}
.stat-low {{background:#4a90d9;}}
.stat-total {{background:#00b894;}}
.stat-box .number {{font-size:36px;font-weight:bold;}}
.stat-box .label {{font-size:14px;opacity:0.8;}}
.issue {{background:#2d2d44;padding:15px;margin:10px 0;border-radius:8px;border-left:4px solid #ccc;}}
.issue.high {{border-color:#ff0040;}}
.issue.medium {{border-color:#ffa500;}}
.issue.low {{border-color:#4a90d9;}}
.issue .sev {{font-weight:bold;display:inline-block;padding:2px 10px;border-radius:12px;font-size:11px;}}
.sev-high {{background:#ff0040;}}
.sev-medium {{background:#ffa500;}}
.sev-low {{background:#4a90d9;}}
.issue .desc {{font-size:16px;margin:5px 0;}}
.issue .location {{font-size:12px;color:#666;font-family:monospace;}}
.issue .details {{font-size:13px;color:#4a90d9;background:#1a1a2e;padding:8px;border-radius:4px;margin-top:5px;font-family:monospace;word-break:break-all;}}
.summary {{background:#2d2d44;padding:20px;border-radius:8px;margin:20px 0;}}
.summary h3 {{color:#00d4ff;}}
.footer {{text-align:center;color:#666;margin-top:30px;font-size:12px;}}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>🔍 Android APK Security Scan Report</h1>
<p>File: {os.path.basename(self.apk_path)}</p>
<p>Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p>Total Issues: {len(self.issues)}</p>
</div>
<div class="stats">
<div class="stat-box stat-high"><div class="number">{len(high)}</div><div class="label">High Severity</div></div>
<div class="stat-box stat-medium"><div class="number">{len(medium)}</div><div class="label">Medium Severity</div></div>
<div class="stat-box stat-low"><div class="number">{len(low)}</div><div class="label">Low Severity</div></div>
<div class="stat-box stat-total"><div class="number">{len(self.issues)}</div><div class="label">Total Issues</div></div>
</div>
<div class="summary"><h3>📊 Summary by Type</h3><ul>"""
        
        type_counts = {}
        for issue in self.issues:
            type_counts[issue['type']] = type_counts.get(issue['type'], 0) + 1
        for t, c in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            html += f'<li>{t.replace("_"," ").title()}: {c}</li>'
        
        html += "</ul></div><div class='issues'><h2>📋 Issues Found</h2>"
        
        if not self.issues:
            html += '<p style="font-size:18px;color:#00b894;">✅ No security issues found!</p>'
        else:
            for issue in self.issues:
                sev = issue['severity'].lower()
                html += f"""
<div class="issue {sev}">
<div><span class="sev sev-{sev}">{issue['severity']}</span> <span style="color:#888;font-size:12px;">{issue['type']}</span></div>
<div class="desc">{issue['description']}</div>
<div class="location">📍 {issue.get('location','Unknown')}</div>
<div class="details">🔍 {issue.get('details','N/A')}</div>
</div>"""
        
        html += f"""</div>
<div class="footer"><p>Generated by Android APK Security Scanner | 100 Ethical Hacking Projects Series</p></div>
</div></body></html>"""
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"{Colors.OKGREEN}[+] Report saved to {self.output_file}{Colors.ENDC}")
    
    def print_summary(self):
        high = [i for i in self.issues if i['severity'] == 'HIGH']
        medium = [i for i in self.issues if i['severity'] == 'MEDIUM']
        low = [i for i in self.issues if i['severity'] == 'LOW']
        
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}  SCAN SUMMARY{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.FAIL}High: {len(high)}{Colors.ENDC}")
        print(f"{Colors.WARNING}Medium: {len(medium)}{Colors.ENDC}")
        print(f"{Colors.DIM}Low: {len(low)}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Total: {len(self.issues)}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Report: {self.output_file}{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
    
    def cleanup(self):
        if self.decompile_dir and os.path.exists(self.decompile_dir):
            try:
                shutil.rmtree(self.decompile_dir)
            except:
                pass
    
    def run(self):
        self.banner()
        if not os.path.exists(self.apk_path):
            print(f"{Colors.FAIL}[-] APK not found{Colors.ENDC}")
            return False
        if not self.decompile_apk():
            return False
        self.parse_manifest()
        self.scan_webview()
        self.scan_strings()
        self.generate_html_report()
        self.print_summary()
        self.cleanup()
        return True

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", required=True)
    parser.add_argument("--output")
    args = parser.parse_args()
    scanner = APKScanner(args.apk, args.output)
    scanner.run()

if __name__ == "__main__":
    main()


# #!/usr/bin/env python3
# """
# ==============================================================
#   PROJECT #23 — Android App Security Scanner (Static Analysis)
#   Scans APK files for security vulnerabilities
# ==============================================================

# FEATURES:
# - Decompile APK using apktool or androguard
# - Extract manifest, resources, classes
# - Scan for hardcoded secrets
# - Detect dangerous permissions
# - Check insecure network settings
# - Identify exported components
# - Find WebView vulnerabilities
# - Generate HTML report

# USAGE:
# --------
#   python apk_scanner.py --apk app.apk
  
#   python apk_scanner.py --apk app.apk --output report.html
  
#   python apk_scanner.py --apk app.apk --verbose

# DEFENSE AGAINST APK REVERSE ENGINEERING:
# 1. ProGuard/Obfuscation - Rename classes, methods, fields
# 2. String Encryption - Encrypt sensitive strings
# 3. Native Code (NDK) - Move critical logic to C/C++
# 4. Anti-debugging - Detect debugger attachments
# 5. Root Detection - Check for root access
# 6. Integrity Checks - Verify APK signature
# 7. Certificate Pinning - Prevent MITM attacks
# 8. Runtime Protection - Obfuscate at runtime
# ==============================================================
# """

# import os
# import sys
# import re
# import json
# import subprocess
# import tempfile
# import shutil
# import xml.etree.ElementTree as ET
# from datetime import datetime
# from pathlib import Path
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

# # YARA-style rules for string scanning
# STRING_RULES = {
#     "api_key": {
#         "patterns": [
#             r'[A-Za-z0-9_\-]{32,64}',
#             r'AIza[0-9A-Za-z-_]{35}',
#             r'sk_live_[0-9a-zA-Z]{24}',
#             r'pk_live_[0-9a-zA-Z]{24}',
#             r'AIzaSy[0-9A-Za-z-_]{33}',
#             r'key[=:]["\']?[A-Za-z0-9_\-]{20,50}["\']?',
#             r'api_key[=:]["\']?[A-Za-z0-9_\-]{20,50}["\']?',
#             r'token[=:]["\']?[A-Za-z0-9_\-]{20,50}["\']?',
#             r'secret[=:]["\']?[A-Za-z0-9_\-]{20,50}["\']?'
#         ],
#         "severity": "HIGH",
#         "description": "Hardcoded API key or secret detected"
#     },
#     "password": {
#         "patterns": [
#             r'password[=:]["\']?[A-Za-z0-9!@#$%^&*()_+]{6,30}["\']?',
#             r'passwd[=:]["\']?[A-Za-z0-9!@#$%^&*()_+]{6,30}["\']?',
#             r'pwd[=:]["\']?[A-Za-z0-9!@#$%^&*()_+]{6,30}["\']?'
#         ],
#         "severity": "HIGH",
#         "description": "Hardcoded password detected"
#     },
#     "jwt_token": {
#         "patterns": [
#             r'eyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}'
#         ],
#         "severity": "HIGH",
#         "description": "JWT token detected"
#     },
#     "aws_key": {
#         "patterns": [
#             r'AKIA[0-9A-Z]{16}',
#             r'ASIA[0-9A-Z]{16}'
#         ],
#         "severity": "HIGH",
#         "description": "AWS access key detected"
#     },
#     "private_key": {
#         "patterns": [
#             r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
#             r'PRIVATE KEY-----',
#             r'-----BEGIN PGP PRIVATE KEY BLOCK-----'
#         ],
#         "severity": "HIGH",
#         "description": "Private key detected"
#     }
# }

# # Dangerous permissions
# DANGEROUS_PERMISSIONS = {
#     "android.permission.READ_SMS": {"severity": "HIGH", "description": "Read SMS messages"},
#     "android.permission.SEND_SMS": {"severity": "HIGH", "description": "Send SMS messages"},
#     "android.permission.RECORD_AUDIO": {"severity": "MEDIUM", "description": "Record audio"},
#     "android.permission.CAMERA": {"severity": "MEDIUM", "description": "Access camera"},
#     "android.permission.READ_CONTACTS": {"severity": "MEDIUM", "description": "Read contacts"},
#     "android.permission.ACCESS_FINE_LOCATION": {"severity": "MEDIUM", "description": "Fine location"},
#     "android.permission.ACCESS_COARSE_LOCATION": {"severity": "MEDIUM", "description": "Coarse location"},
#     "android.permission.READ_EXTERNAL_STORAGE": {"severity": "LOW", "description": "Read external storage"},
#     "android.permission.WRITE_EXTERNAL_STORAGE": {"severity": "LOW", "description": "Write external storage"},
#     "android.permission.READ_PHONE_STATE": {"severity": "HIGH", "description": "Read phone state"},
#     "android.permission.PROCESS_OUTGOING_CALLS": {"severity": "HIGH", "description": "Process outgoing calls"},
#     "android.permission.SYSTEM_ALERT_WINDOW": {"severity": "MEDIUM", "description": "System alert window"},
#     "android.permission.WAKE_LOCK": {"severity": "LOW", "description": "Keep device awake"}
# }

# class APKScanner:
#     def __init__(self, apk_path, output_file=None, verbose=False):
#         self.apk_path = apk_path
#         self.output_file = output_file or "scan_report.html"
#         self.verbose = verbose
#         self.issues = []
#         self.decompile_dir = None
#         self.manifest_path = None
#         self.strings_file = None
        
#     def banner(self):
#         """Display banner"""
#         print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
#         print(f"{Colors.HEADER}  PROJECT #23 — Android App Security Scanner{Colors.ENDC}")
#         print(f"{Colors.OKBLUE}  Static Analysis of Android APK Files{Colors.ENDC}")
#         print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
#         print(f"{Colors.OKGREEN}[+] APK: {self.apk_path}{Colors.ENDC}")
#         print(f"{Colors.OKGREEN}[+] Output: {self.output_file}{Colors.ENDC}")
#         print()
    
#     def check_dependencies(self):
#         """Check if required tools are installed"""
#         dependencies = ['apktool', 'aapt', 'jadx']
#         missing = []
        
#         for dep in dependencies:
#             if shutil.which(dep) is None:
#                 missing.append(dep)
        
#         if missing:
#             print(f"{Colors.WARNING}[!] Missing dependencies: {', '.join(missing)}{Colors.ENDC}")
#             print(f"{Colors.DIM}[*] Install with: sudo apt install apktool aapt jadx{Colors.ENDC}")
#             print(f"{Colors.DIM}[*] Or use: pip install androguard{Colors.ENDC}")
#             return False
        
#         return True
    
#     def decompile_apk(self):
#         """Decompile APK using apktool"""
#         print(f"{Colors.OKBLUE}[*] Decompiling APK...{Colors.ENDC}")
        
#         # Create temporary directory
#         self.decompile_dir = tempfile.mkdtemp(prefix='apk_scan_')
        
#         try:
#             # Run apktool
#             cmd = ['apktool', 'd', '-f', '-o', self.decompile_dir, self.apk_path]
#             result = subprocess.run(cmd, capture_output=True, text=True)
            
#             if result.returncode != 0:
#                 print(f"{Colors.FAIL}[-] Decompile failed: {result.stderr}{Colors.ENDC}")
#                 return False
            
#             # Locate manifest and files
#             self.manifest_path = os.path.join(self.decompile_dir, 'AndroidManifest.xml')
            
#             # Also extract strings using androguard
#             try:
#                 import androguard
#                 from androguard.core.bytecodes.apk import APK
                
#                 apk = APK(self.apk_path)
#                 all_strings = []
                
#                 # Extract from manifest
#                 all_strings.extend(apk.get_android_manifest_xml().toxml().split('\n'))
                
#                 # Extract from resources
#                 for string in apk.get_arsc_strings():
#                     all_strings.append(string)
                
#                 self.strings_file = os.path.join(self.decompile_dir, 'strings.txt')
#                 with open(self.strings_file, 'w', encoding='utf-8', errors='ignore') as f:
#                     f.write('\n'.join(all_strings))
                
#                 print(f"{Colors.OKGREEN}[+] Decompiled successfully{Colors.ENDC}")
#                 return True
                
#             except ImportError:
#                 print(f"{Colors.WARNING}[!] androguard not installed, using basic decompile{Colors.ENDC}")
#                 print(f"{Colors.OKGREEN}[+] Decompiled successfully (basic){Colors.ENDC}")
#                 return True
                
#         except Exception as e:
#             print(f"{Colors.FAIL}[-] Decompile error: {e}{Colors.ENDC}")
#             return False
    
#     def parse_manifest(self):
#         """Parse AndroidManifest.xml for security issues"""
#         print(f"{Colors.OKBLUE}[*] Analyzing manifest...{Colors.ENDC}")
        
#         if not self.manifest_path or not os.path.exists(self.manifest_path):
#             print(f"{Colors.WARNING}[!] Manifest not found{Colors.ENDC}")
#             return
        
#         try:
#             tree = ET.parse(self.manifest_path)
#             root = tree.getroot()
            
#             # Check for allowBackup
#             allow_backup = root.get('android:allowBackup')
#             if allow_backup and allow_backup.lower() == 'true':
#                 self.issues.append({
#                     'type': 'INSECURE_SETTING',
#                     'severity': 'MEDIUM',
#                     'description': 'allowBackup=true - App data can be backed up',
#                     'location': 'AndroidManifest.xml',
#                     'details': 'android:allowBackup="true"'
#                 })
            
#             # Check for usesCleartextTraffic
#             cleartext = root.get('android:usesCleartextTraffic')
#             if cleartext and cleartext.lower() == 'true':
#                 self.issues.append({
#                     'type': 'INSECURE_SETTING',
#                     'severity': 'HIGH',
#                     'description': 'usesCleartextTraffic=true - App allows plaintext network traffic',
#                     'location': 'AndroidManifest.xml',
#                     'details': 'android:usesCleartextTraffic="true"'
#                 })
            
#             # Check for debug mode
#             debug = root.get('android:debuggable')
#             if debug and debug.lower() == 'true':
#                 self.issues.append({
#                     'type': 'INSECURE_SETTING',
#                     'severity': 'HIGH',
#                     'description': 'android:debuggable=true - App is debuggable',
#                     'location': 'AndroidManifest.xml',
#                     'details': 'android:debuggable="true"'
#                 })
            
#             # Parse permissions
#             for perm in root.findall('.//uses-permission'):
#                 perm_name = perm.get('android:name')
#                 if perm_name in DANGEROUS_PERMISSIONS:
#                     info = DANGEROUS_PERMISSIONS[perm_name]
#                     self.issues.append({
#                         'type': 'DANGEROUS_PERMISSION',
#                         'severity': info['severity'],
#                         'description': info['description'],
#                         'location': 'AndroidManifest.xml',
#                         'details': perm_name
#                     })
            
#             # Check exported components
#             for component in root.findall('.//activity') + root.findall('.//service') + root.findall('.//receiver'):
#                 exported = component.get('android:exported')
#                 if exported and exported.lower() == 'true':
#                     comp_name = component.get('android:name', 'Unknown')
#                     comp_type = 'Activity' if component.tag == 'activity' else ('Service' if component.tag == 'service' else 'Receiver')
#                     self.issues.append({
#                         'type': 'EXPORTED_COMPONENT',
#                         'severity': 'MEDIUM',
#                         'description': f'Exported {comp_type} may be accessible by other apps',
#                         'location': 'AndroidManifest.xml',
#                         'details': f'{comp_type}: {comp_name}'
#                     })
            
#             # Check for intent-filter with scheme
#             for activity in root.findall('.//activity'):
#                 for intent_filter in activity.findall('.//intent-filter'):
#                     for data in intent_filter.findall('.//data'):
#                         scheme = data.get('android:scheme')
#                         if scheme:
#                             self.issues.append({
#                                 'type': 'DEEPLINK_EXPOSED',
#                                 'severity': 'LOW',
#                                 'description': f'Deep link scheme exposed: {scheme}',
#                                 'location': 'AndroidManifest.xml',
#                                 'details': f'scheme="{scheme}"'
#                             })
            
#             print(f"{Colors.OKGREEN}[+] Manifest analysis complete{Colors.ENDC}")
            
#         except ET.ParseError as e:
#             print(f"{Colors.FAIL}[-] Failed to parse manifest: {e}{Colors.ENDC}")
    
#     def scan_strings(self):
#         """Scan strings for hardcoded secrets"""
#         print(f"{Colors.OKBLUE}[*] Scanning for hardcoded secrets...{Colors.ENDC}")
        
#         if not self.strings_file or not os.path.exists(self.strings_file):
#             print(f"{Colors.WARNING}[!] Strings file not found{Colors.ENDC}")
#             return
        
#         try:
#             with open(self.strings_file, 'r', encoding='utf-8', errors='ignore') as f:
#                 content = f.read()
            
#             for rule_name, rule in STRING_RULES.items():
#                 for pattern in rule['patterns']:
#                     matches = re.finditer(pattern, content, re.IGNORECASE)
#                     for match in matches:
#                         self.issues.append({
#                             'type': 'HARDCODED_SECRET',
#                             'severity': rule['severity'],
#                             'description': rule['description'],
#                             'location': 'strings',
#                             'details': match.group()
#                         })
#                         break  # Only report one match per pattern
            
#             print(f"{Colors.OKGREEN}[+] String scan complete{Colors.ENDC}")
            
#         except Exception as e:
#             print(f"{Colors.FAIL}[-] Failed to scan strings: {e}{Colors.ENDC}")
    
#     def scan_webview(self):
#         """Scan for WebView vulnerabilities"""
#         print(f"{Colors.OKBLUE}[*] Scanning for WebView vulnerabilities...{Colors.ENDC}")
        
#         # Look for WebView in decompiled files
#         webview_patterns = [
#             (r'setJavaScriptEnabled\(\s*true\s*\)', 'MEDIUM', 'WebView with JavaScript enabled (XSS risk)'),
#             (r'addJavascriptInterface\(', 'HIGH', 'JavaScript interface exposed (RCE risk)'),
#             (r'setAllowUniversalAccessFromFileURLs\(\s*true\s*\)', 'HIGH', 'File URL access enabled'),
#             (r'loadUrl\(\s*["\'][^"\']*["\']', 'LOW', 'WebView URL loading - check for dynamic URLs')
#         ]
        
#         if not self.decompile_dir:
#             return
        
#         try:
#             # Search through all files
#             for root, dirs, files in os.walk(self.decompile_dir):
#                 for file in files:
#                     if file.endswith(('.smali', '.java', '.xml')):
#                         file_path = os.path.join(root, file)
#                         with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
#                             content = f.read()
                            
#                             for pattern, severity, desc in webview_patterns:
#                                 if re.search(pattern, content, re.IGNORECASE):
#                                     self.issues.append({
#                                         'type': 'WEBVIEW_VULNERABILITY',
#                                         'severity': severity,
#                                         'description': desc,
#                                         'location': file_path,
#                                         'details': pattern
#                                     })
            
#             print(f"{Colors.OKGREEN}[+] WebView scan complete{Colors.ENDC}")
            
#         except Exception as e:
#             print(f"{Colors.FAIL}[-] WebView scan error: {e}{Colors.ENDC}")
    
#     def generate_html_report(self):
#         """Generate HTML report"""
#         print(f"{Colors.OKBLUE}[*] Generating HTML report...{Colors.ENDC}")
        
#         # Count issues by severity
#         high = [i for i in self.issues if i['severity'] == 'HIGH']
#         medium = [i for i in self.issues if i['severity'] == 'MEDIUM']
#         low = [i for i in self.issues if i['severity'] == 'LOW']
        
#         html = f"""
# <!DOCTYPE html>
# <html>
# <head>
#     <meta charset="UTF-8">
#     <title>Android APK Security Scan Report</title>
#     <style>
#         * {{ margin: 0; padding: 0; box-sizing: border-box; }}
#         body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #1a1a2e; color: #e0e0e0; padding: 20px; }}
#         .container {{ max-width: 1200px; margin: 0 auto; }}
#         .header {{ background: linear-gradient(135deg, #16213e, #0f3460); padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
#         .header h1 {{ color: #00d4ff; font-size: 28px; }}
#         .header p {{ color: #aaa; margin-top: 10px; }}
#         .stats {{ display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }}
#         .stat-box {{ flex: 1; min-width: 150px; padding: 20px; border-radius: 8px; text-align: center; }}
#         .stat-high {{ background: #ff0040; }}
#         .stat-medium {{ background: #ffa500; }}
#         .stat-low {{ background: #4a90d9; }}
#         .stat-total {{ background: #00b894; }}
#         .stat-box .number {{ font-size: 36px; font-weight: bold; }}
#         .stat-box .label {{ font-size: 14px; opacity: 0.8; }}
#         .issue {{
#             background: #2d2d44; padding: 15px; margin: 10px 0; border-radius: 8px;
#             border-left: 4px solid #ccc; display: flex; align-items: flex-start;
#         }}
#         .issue.high {{ border-color: #ff0040; }}
#         .issue.medium {{ border-color: #ffa500; }}
#         .issue.low {{ border-color: #4a90d9; }}
#         .issue .severity {{ font-weight: bold; min-width: 80px; }}
#         .issue .severity.high {{ color: #ff0040; }}
#         .issue .severity.medium {{ color: #ffa500; }}
#         .issue .severity.low {{ color: #4a90d9; }}
#         .issue .content {{ flex: 1; }}
#         .issue .type {{ font-size: 12px; color: #888; text-transform: uppercase; letter-spacing: 1px; }}
#         .issue .desc {{ font-size: 16px; margin: 5px 0; }}
#         .issue .location {{ font-size: 12px; color: #666; font-family: monospace; }}
#         .issue .details {{ font-size: 13px; color: #4a90d9; background: #1a1a2e; padding: 8px; border-radius: 4px; margin-top: 5px; font-family: monospace; word-break: break-all; }}
#         .summary {{ background: #2d2d44; padding: 20px; border-radius: 8px; margin: 20px 0; }}
#         .summary h3 {{ color: #00d4ff; margin-bottom: 10px; }}
#         .summary ul {{ list-style: none; }}
#         .summary li {{ padding: 5px 0; border-bottom: 1px solid #3d3d5a; }}
#         .footer {{ text-align: center; color: #666; margin-top: 30px; font-size: 12px; }}
#         .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: bold; }}
#         .badge.high {{ background: #ff0040; }}
#         .badge.medium {{ background: #ffa500; }}
#         .badge.low {{ background: #4a90d9; }}
#         .clear {{ color: #00b894; }}
#         .clear-text {{ color: #e0e0e0; }}
#     </style>
# </head>
# <body>
#     <div class="container">
#         <div class="header">
#             <h1>🔍 Android APK Security Scan Report</h1>
#             <p>File: {os.path.basename(self.apk_path)}</p>
#             <p>Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
#             <p>Total Issues: {len(self.issues)}</p>
#         </div>
        
#         <div class="stats">
#             <div class="stat-box stat-high">
#                 <div class="number">{len(high)}</div>
#                 <div class="label">High Severity</div>
#             </div>
#             <div class="stat-box stat-medium">
#                 <div class="number">{len(medium)}</div>
#                 <div class="label">Medium Severity</div>
#             </div>
#             <div class="stat-box stat-low">
#                 <div class="number">{len(low)}</div>
#                 <div class="label">Low Severity</div>
#             </div>
#             <div class="stat-box stat-total">
#                 <div class="number">{len(self.issues)}</div>
#                 <div class="label">Total Issues</div>
#             </div>
#         </div>
        
#         <div class="summary">
#             <h3>📊 Summary by Type</h3>
#             <ul>
# """
        
#         # Group by type
#         type_counts = {}
#         for issue in self.issues:
#             type_counts[issue['type']] = type_counts.get(issue['type'], 0) + 1
        
#         for issue_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
#             html += f'<li>{issue_type.replace("_", " ").title()}: {count}</li>\n'
        
#         html += """
#             </ul>
#         </div>
        
#         <div class="issues">
#             <h2 style="margin-bottom: 15px;">📋 Issues Found</h2>
# """
        
#         if not self.issues:
#             html += '<div class="clear"><p style="font-size: 18px;">✅ No security issues found!</p></div>'
#         else:
#             for issue in self.issues:
#                 severity_class = issue['severity'].lower()
#                 html += f"""
#             <div class="issue {severity_class}">
#                 <div class="severity {severity_class}">{issue['severity']}</div>
#                 <div class="content">
#                     <div class="type">{issue['type']}</div>
#                     <div class="desc">{issue['description']}</div>
#                     <div class="location">📍 {issue.get('location', 'Unknown')}</div>
#                     <div class="details">🔍 {issue.get('details', 'N/A')}</div>
#                 </div>
#             </div>
# """
        
#         html += f"""
#         </div>
        
#         <div class="footer">
#             <p>Generated by Android APK Security Scanner | 100 Ethical Hacking Projects Series</p>
#             <p>© 2024 - For Educational Purposes Only</p>
#         </div>
#     </div>
# </body>
# </html>
# """
        
#         # Write HTML file
#         with open(self.output_file, 'w', encoding='utf-8') as f:
#             f.write(html)
        
#         print(f"{Colors.OKGREEN}[+] Report saved to {self.output_file}{Colors.ENDC}")
#         return self.output_file
    
#     def print_summary(self):
#         """Print summary to console"""
#         if not self.issues:
#             print(f"\n{Colors.OKGREEN}{'='*80}{Colors.ENDC}")
#             print(f"{Colors.OKGREEN}[✓] No security issues found!{Colors.ENDC}")
#             print(f"{Colors.OKGREEN}{'='*80}{Colors.ENDC}")
#             return
        
#         high = [i for i in self.issues if i['severity'] == 'HIGH']
#         medium = [i for i in self.issues if i['severity'] == 'MEDIUM']
#         low = [i for i in self.issues if i['severity'] == 'LOW']
        
#         print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
#         print(f"{Colors.HEADER}  SCAN SUMMARY{Colors.ENDC}")
#         print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        
#         print(f"\n{Colors.FAIL}High Severity: {len(high)}{Colors.ENDC}")
#         print(f"{Colors.WARNING}Medium Severity: {len(medium)}{Colors.ENDC}")
#         print(f"{Colors.DIM}Low Severity: {len(low)}{Colors.ENDC}")
#         print(f"{Colors.OKGREEN}Total Issues: {len(self.issues)}{Colors.ENDC}")
        
#         if high:
#             print(f"\n{Colors.FAIL}High Severity Issues:{Colors.ENDC}")
#             for issue in high[:5]:
#                 print(f"  {Colors.FAIL}• {issue['description']}{Colors.ENDC}")
#                 print(f"    {Colors.DIM}  → {issue.get('details', '')}{Colors.ENDC}")
        
#         print(f"\n{Colors.OKGREEN}[+] Report: {self.output_file}{Colors.ENDC}")
#         print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
    
#     def cleanup(self):
#         """Clean up temporary files"""
#         if self.decompile_dir and os.path.exists(self.decompile_dir):
#             try:
#                 shutil.rmtree(self.decompile_dir)
#                 if self.verbose:
#                     print(f"{Colors.DIM}[*] Cleaned up temporary files{Colors.ENDC}")
#             except:
#                 pass
    
#     def run(self):
#         """Main execution"""
#         self.banner()
        
#         # Check if APK exists
#         if not os.path.exists(self.apk_path):
#             print(f"{Colors.FAIL}[-] APK file not found: {self.apk_path}{Colors.ENDC}")
#             return False
        
#         # Decompile
#         if not self.decompile_apk():
#             print(f"{Colors.FAIL}[-] Failed to decompile APK{Colors.ENDC}")
#             return False
        
#         # Parse manifest
#         self.parse_manifest()
        
#         # Scan strings
#         self.scan_strings()
        
#         # Scan WebView
#         self.scan_webview()
        
#         # Generate report
#         self.generate_html_report()
        
#         # Print summary
#         self.print_summary()
        
#         # Cleanup
#         self.cleanup()
        
#         return True

# def main():
#     import argparse
    
#     parser = argparse.ArgumentParser(description="Android APK Security Scanner")
#     parser.add_argument("--apk", required=True, help="APK file path")
#     parser.add_argument("--output", help="HTML report file (default: scan_report.html)")
#     parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
#     args = parser.parse_args()
    
#     scanner = APKScanner(args.apk, args.output, args.verbose)
    
#     try:
#         scanner.run()
#     except KeyboardInterrupt:
#         print(f"\n{Colors.WARNING}[!] Scan interrupted{Colors.ENDC}")
#         scanner.cleanup()
#     except Exception as e:
#         print(f"{Colors.FAIL}[-] Error: {e}{Colors.ENDC}")
#         scanner.cleanup()

# if __name__ == "__main__":
#     main()