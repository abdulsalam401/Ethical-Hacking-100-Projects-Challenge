#!/usr/bin/env python3
"""
==============================================================
  PROJECT #27 — File Integrity Monitor (FIM) with Tripwire-style
  Monitors file system changes using SHA-256 hashes
==============================================================
"""

import os
import sys
import json
import hashlib
import time
import argparse
import datetime
from pathlib import Path
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

class FileIntegrityMonitor:
    def __init__(self, target_dir, output_file="baseline.json", 
                 exclusions=None, verbose=False):
        self.target_dir = os.path.abspath(target_dir)
        self.output_file = output_file
        self.exclusions = exclusions or []
        self.verbose = verbose
        self.baseline_data = {}
        self.changes = {
            'added': [],
            'deleted': [],
            'modified': [],
            'permission_changed': []
        }
        self.scan_time = 0
        self.total_files = 0
        
    def banner(self, mode):
        """Display banner"""
        mode_text = "BASELINE CREATION" if mode == 'baseline' else "INTEGRITY CHECK"
        color = Colors.OKGREEN if mode == 'baseline' else Colors.HEADER
        
        print(f"\n{color}{'='*80}{Colors.ENDC}")
        print(f"{color}  PROJECT #27 — File Integrity Monitor (FIM){Colors.ENDC}")
        print(f"{color}  {mode_text}{Colors.ENDC}")
        print(f"{color}{'='*80}{Colors.ENDC}\n")
        
        print(f"{Colors.OKGREEN}[+] Target: {self.target_dir}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Exclusions: {self.exclusions}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Baseline: {self.output_file}{Colors.ENDC}")
        print()
    
    def is_excluded(self, filepath):
        """Check if file should be excluded"""
        filename = os.path.basename(filepath)
        for pattern in self.exclusions:
            if pattern.startswith('*.'):
                if filename.endswith(pattern[1:]):
                    return True
            elif pattern.endswith('/'):
                if filepath.startswith(os.path.join(self.target_dir, pattern[:-1])):
                    return True
            elif pattern in filepath:
                return True
        return False
    
    def get_file_hash(self, filepath):
        """Compute SHA-256 hash of file"""
        try:
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            if self.verbose:
                print(f"{Colors.DIM}[!] Error hashing {filepath}: {e}{Colors.ENDC}")
            return None
    
    def get_file_metadata(self, filepath):
        """Get file metadata"""
        try:
            stat = os.stat(filepath)
            return {
                'size': stat.st_size,
                'permissions': oct(stat.st_mode & 0o777)[2:],
                'mtime': stat.st_mtime,
                'uid': stat.st_uid,
                'gid': stat.st_gid
            }
        except Exception as e:
            if self.verbose:
                print(f"{Colors.DIM}[!] Error getting metadata for {filepath}: {e}{Colors.ENDC}")
            return None
    
    def scan_directory(self):
        """Recursively scan directory"""
        print(f"{Colors.OKBLUE}[*] Scanning directory...{Colors.ENDC}")
        
        files = {}
        self.total_files = 0
        start_time = time.time()
        
        for root, dirs, filenames in os.walk(self.target_dir):
            for filename in filenames:
                filepath = os.path.join(root, filename)
                rel_path = os.path.relpath(filepath, self.target_dir)
                
                if self.is_excluded(rel_path):
                    if self.verbose:
                        print(f"{Colors.DIM}[*] Excluding: {rel_path}{Colors.ENDC}")
                    continue
                
                file_hash = self.get_file_hash(filepath)
                metadata = self.get_file_metadata(filepath)
                
                if file_hash and metadata:
                    files[rel_path] = {
                        'hash': file_hash,
                        'size': metadata['size'],
                        'permissions': metadata['permissions'],
                        'mtime': metadata['mtime'],
                        'uid': metadata['uid'],
                        'gid': metadata['gid']
                    }
                    self.total_files += 1
                    
                    if self.verbose:
                        print(f"{Colors.DIM}[*] Processed: {rel_path}{Colors.ENDC}")
        
        self.scan_time = time.time() - start_time
        print(f"{Colors.OKGREEN}[+] Scanned {self.total_files} files in {self.scan_time:.2f}s{Colors.ENDC}")
        
        return files
    
    def create_baseline(self):
        """Create baseline snapshot"""
        self.banner('baseline')
        
        baseline = {
            'created': datetime.datetime.now().isoformat(),
            'target': self.target_dir,
            'exclusions': self.exclusions,
            'total_files': 0,
            'files': {}
        }
        
        files = self.scan_directory()
        baseline['files'] = files
        baseline['total_files'] = len(files)
        
        try:
            with open(self.output_file, 'w') as f:
                json.dump(baseline, f, indent=2)
            print(f"{Colors.OKGREEN}[+] Baseline saved to {self.output_file}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] Failed to save baseline: {e}{Colors.ENDC}")
            return False
        
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}  BASELINE CREATED{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Files tracked: {len(files)}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Target: {self.target_dir}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Created: {baseline['created']}{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        return True
    
    def load_baseline(self):
        """Load baseline from file"""
        try:
            with open(self.output_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"{Colors.FAIL}[-] Baseline not found: {self.output_file}{Colors.ENDC}")
            print(f"{Colors.WARNING}[!] Run with --baseline first{Colors.ENDC}")
            return None
        except Exception as e:
            print(f"{Colors.FAIL}[-] Failed to load baseline: {e}{Colors.ENDC}")
            return None
    
    def check_integrity(self):
        """Check integrity against baseline"""
        self.banner('check')
        
        baseline = self.load_baseline()
        if not baseline:
            return False
        
        baseline_files = baseline.get('files', {})
        print(f"{Colors.OKGREEN}[+] Baseline loaded: {len(baseline_files)} files{Colors.ENDC}")
        
        current_files = self.scan_directory()
        
        print(f"\n{Colors.OKBLUE}[*] Comparing files...{Colors.ENDC}")
        
        for rel_path, baseline_info in baseline_files.items():
            if rel_path not in current_files:
                self.changes['deleted'].append(rel_path)
                print(f"{Colors.FAIL}[!] DELETED: {rel_path}{Colors.ENDC}")
            else:
                current_info = current_files[rel_path]
                
                if baseline_info['hash'] != current_info['hash']:
                    self.changes['modified'].append({
                        'file': rel_path,
                        'old_hash': baseline_info['hash'][:8],
                        'new_hash': current_info['hash'][:8]
                    })
                    print(f"{Colors.FAIL}[!] MODIFIED: {rel_path} (content changed){Colors.ENDC}")
                
                elif baseline_info['permissions'] != current_info['permissions']:
                    self.changes['permission_changed'].append({
                        'file': rel_path,
                        'old_perms': baseline_info['permissions'],
                        'new_perms': current_info['permissions']
                    })
                    print(f"{Colors.WARNING}[!] PERMISSION CHANGE: {rel_path} {baseline_info['permissions']} -> {current_info['permissions']}{Colors.ENDC}")
        
        for rel_path in current_files:
            if rel_path not in baseline_files:
                self.changes['added'].append(rel_path)
                print(f"{Colors.OKGREEN}[+] ADDED: {rel_path}{Colors.ENDC}")
        
        self.display_summary()
        return True
    
    def display_summary(self):
        """Display change summary"""
        total_changes = sum(len(v) for v in self.changes.values())
        
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}  INTEGRITY CHECK COMPLETE{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        
        print(f"{Colors.OKGREEN}[+] Files scanned: {self.total_files}{Colors.ENDC}")
        print(f"{Colors.FAIL}[!] Total changes: {total_changes}{Colors.ENDC}")
        
        if self.changes['added']:
            print(f"{Colors.OKGREEN}[+] Added: {len(self.changes['added'])}{Colors.ENDC}")
        if self.changes['deleted']:
            print(f"{Colors.FAIL}[!] Deleted: {len(self.changes['deleted'])}{Colors.ENDC}")
        if self.changes['modified']:
            print(f"{Colors.FAIL}[!] Modified: {len(self.changes['modified'])}{Colors.ENDC}")
        if self.changes['permission_changed']:
            print(f"{Colors.WARNING}[!] Permission changes: {len(self.changes['permission_changed'])}{Colors.ENDC}")
        
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        if total_changes == 0:
            print(f"{Colors.OKGREEN}[✓] No changes detected. System is clean.{Colors.ENDC}\n")
    
    def generate_report(self, report_file):
        """Generate HTML report"""
        if not self.changes or sum(len(v) for v in self.changes.values()) == 0:
            print(f"{Colors.WARNING}[!] No changes to report{Colors.ENDC}")
            return
        
        total_changes = sum(len(v) for v in self.changes.values())
        
        html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>File Integrity Monitor Report</title>
<style>
body {{font-family:'Segoe UI',sans-serif;background:#1a1a2e;color:#e0e0e0;padding:20px;}}
.container {{max-width:1200px;margin:0 auto;}}
.header {{background:linear-gradient(135deg,#16213e,#0f3460);padding:30px;border-radius:10px;}}
.header h1 {{color:#00d4ff;}}
.stats {{display:flex;gap:20px;margin:20px 0;flex-wrap:wrap;}}
.stat-box {{flex:1;min-width:120px;padding:20px;border-radius:8px;text-align:center;}}
.stat-added {{background:#00b894;}}
.stat-deleted {{background:#ff0040;}}
.stat-modified {{background:#ffa500;}}
.stat-permission {{background:#4a90d9;}}
.stat-total {{background:#6c5ce7;}}
.stat-box .number {{font-size:36px;font-weight:bold;}}
.stat-box .label {{font-size:14px;opacity:0.8;}}
.change {{background:#2d2d44;padding:15px;margin:10px 0;border-radius:8px;border-left:4px solid #ccc;}}
.change.added {{border-color:#00b894;}}
.change.deleted {{border-color:#ff0040;}}
.change.modified {{border-color:#ffa500;}}
.change.permission {{border-color:#4a90d9;}}
.change .type {{font-weight:bold;padding:2px 10px;border-radius:12px;font-size:11px;}}
.type-added {{background:#00b894;}}
.type-deleted {{background:#ff0040;}}
.type-modified {{background:#ffa500;}}
.type-permission {{background:#4a90d9;}}
.change .file {{font-size:16px;font-family:monospace;}}
.change .details {{font-size:13px;color:#aaa;}}
.footer {{text-align:center;color:#666;margin-top:30px;}}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>🔍 File Integrity Monitor Report</h1>
<p>Target: {self.target_dir}</p>
<p>Report Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</div>
<div class="stats">
<div class="stat-box stat-added"><div class="number">{len(self.changes['added'])}</div><div class="label">Added</div></div>
<div class="stat-box stat-deleted"><div class="number">{len(self.changes['deleted'])}</div><div class="label">Deleted</div></div>
<div class="stat-box stat-modified"><div class="number">{len(self.changes['modified'])}</div><div class="label">Modified</div></div>
<div class="stat-box stat-permission"><div class="number">{len(self.changes['permission_changed'])}</div><div class="label">Permission</div></div>
<div class="stat-box stat-total"><div class="number">{total_changes}</div><div class="label">Total</div></div>
</div>
<h2>📋 Changes Detected</h2>"""
        
        for filepath in self.changes['added']:
            html += f"""
<div class="change added"><div><span class="type type-added">ADDED</span></div>
<div class="file">📄 {filepath}</div></div>"""
        
        for filepath in self.changes['deleted']:
            html += f"""
<div class="change deleted"><div><span class="type type-deleted">DELETED</span></div>
<div class="file">🗑️ {filepath}</div></div>"""
        
        for change in self.changes['modified']:
            html += f"""
<div class="change modified"><div><span class="type type-modified">MODIFIED</span></div>
<div class="file">📝 {change['file']}</div>
<div class="details">Hash: {change['old_hash']} → {change['new_hash']}</div></div>"""
        
        for change in self.changes['permission_changed']:
            html += f"""
<div class="change permission"><div><span class="type type-permission">PERMISSION</span></div>
<div class="file">🔐 {change['file']}</div>
<div class="details">{change['old_perms']} → {change['new_perms']}</div></div>"""
        
        html += f"""
<div class="footer"><p>Generated by File Integrity Monitor | 100 Ethical Hacking Projects Series</p></div>
</div></body></html>"""
        
        try:
            with open(report_file, 'w') as f:
                f.write(html)
            print(f"{Colors.OKGREEN}[+] Report saved to {report_file}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] Failed to save report: {e}{Colors.ENDC}")
    
    def print_defenses(self):
        """Print defense mechanisms"""
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}  DEFENSE AGAINST FILE INTEGRITY ATTACKS{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        
        defenses = [
            ("File Integrity Monitoring", "Detect unauthorized changes in real-time"),
            ("Tripwire-style Baselines", "Known good state for comparison"),
            ("Signed/Encrypted Baselines", "Prevent tampering with baseline files"),
            ("Real-time Monitoring", "Detect changes immediately"),
            ("Offline Storage", "Store baselines offline for verification"),
            ("Read-only Filesystems", "Prevent modifications to critical files"),
            ("SELinux/AppArmor", "Restrict file access with MAC"),
            ("Auditd", "Log all file access for forensics")
        ]
        
        for title, desc in defenses:
            print(f"{Colors.OKGREEN}{title}{Colors.ENDC}: {Colors.DIM}{desc}{Colors.ENDC}")
        
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")

def main():
    parser = argparse.ArgumentParser(description="File Integrity Monitor")
    parser.add_argument("--baseline", action="store_true", help="Create baseline snapshot")
    parser.add_argument("--check", action="store_true", help="Check against baseline")
    parser.add_argument("--target", required=True, help="Target directory")
    parser.add_argument("--output", default="baseline.json", help="Baseline file (for --baseline)")
    parser.add_argument("--baseline-file", default="baseline.json", help="Baseline file to check against")
    parser.add_argument("--exclude", action="append", help="Exclude pattern (e.g., *.log)")
    parser.add_argument("--report", help="Generate HTML report")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--defenses", action="store_true", help="Show defense mechanisms")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.target):
        print(f"{Colors.FAIL}[-] Target not found: {args.target}{Colors.ENDC}")
        sys.exit(1)
    
    if args.baseline:
        # Create baseline
        monitor = FileIntegrityMonitor(
            target_dir=args.target,
            output_file=args.output,
            exclusions=args.exclude or [],
            verbose=args.verbose
        )
        monitor.create_baseline()
        
    elif args.check:
        # Check integrity
        monitor = FileIntegrityMonitor(
            target_dir=args.target,
            output_file=args.baseline_file,
            exclusions=args.exclude or [],
            verbose=args.verbose
        )
        monitor.check_integrity()
        if args.report:
            monitor.generate_report(args.report)
    else:
        print(f"{Colors.WARNING}[!] Specify --baseline or --check{Colors.ENDC}")
    
    if args.defenses:
        monitor.print_defenses()

if __name__ == "__main__":
    main()