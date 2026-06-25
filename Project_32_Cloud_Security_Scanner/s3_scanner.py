#!/usr/bin/env python3
"""
PROJECT #32 — AWS S3 Bucket Scanner
"""

import os
import sys
import time
import re
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Colorama with fallback
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

# Colors class with ALL needed colors
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

# Try to import boto3
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    print("[-] boto3 not installed. Run: pip install boto3")

# Default wordlist
DEFAULT_WORDLIST = [
    'backup', 'backups', 'data', 'files', 'uploads', 'downloads',
    'public', 'private', 'assets', 'static', 'media', 'images',
    'docs', 'documents', 'config', 'conf', 'logs', 'log',
    'temp', 'tmp', 'cache', 'archive', 'storage', 'content',
    'user-data', 'userdata', 'user-uploads', 'profile-pics',
    'company', 'company-data', 'company-backups',
    'prod', 'production', 'dev', 'development', 'test', 'staging',
    'stage', 'qa', 'demo', 'example', 'sample',
    'app', 'api', 'web', 'www', 'mobile', 'ios', 'android',
    'database', 'db-backup', 'sql', 'mysql', 'postgres',
    'elasticsearch', 'es', 'redis', 'cache',
    'cloudformation', 'cloudfront', 'ec2', 's3', 'lambda',
    'bucket', 'buckets', 'my-bucket', 'mybucket',
    'security', 'audit', 'compliance', 'forensics',
    'pen-test', 'pentest', 'vulnerability',
    'backup-2024', 'backup-2023', 'data-backup',
    'logs-2024', 'logs-2023',
]

# Sensitive file patterns
SENSITIVE_PATTERNS = [
    r'\.env$', r'\.pem$', r'\.key$', r'\.crt$', r'\.p12$', r'\.pfx$',
    r'credentials', r'config\.json$', r'config\.yml$', r'config\.yaml$',
    r'\.aws/credentials', r'secret', r'password', r'api_key', r'token',
    r'\.sql$', r'\.dump$', r'\.bak$', r'\.backup$', r'\.old$',
    r'\.swp$', r'\.tmp$', r'\.log$',
]

class S3Scanner:
    def __init__(self, prefixes=None, wordlist=None, rate_limit=10, max_threads=20, output_file="s3_report.html"):
        self.prefixes = prefixes or []
        self.wordlist = wordlist or DEFAULT_WORDLIST
        self.rate_limit = rate_limit
        self.max_threads = max_threads
        self.output_file = output_file
        self.s3_client = None
        self.findings = []
        self.public_buckets = []
        self.sensitive_files = []
        self.request_count = 0
        self.lock = threading.Lock()
        
    def connect(self):
        if not BOTO3_AVAILABLE:
            return False
        try:
            self.s3_client = boto3.client('s3')
            self.s3_client.list_buckets()
            print(f"{Colors.OKGREEN}[+] Connected to AWS S3{Colors.ENDC}")
            return True
        except NoCredentialsError:
            print(f"{Colors.WARNING}[!] No AWS credentials found. Using anonymous access.{Colors.ENDC}")
            self.s3_client = boto3.client('s3', aws_access_key_id='', aws_secret_access_key='')
            return True
        except Exception as e:
            print(f"{Colors.FAIL}[-] Failed to connect: {e}{Colors.ENDC}")
            try:
                self.s3_client = boto3.client('s3', aws_access_key_id='', aws_secret_access_key='')
                return True
            except:
                return False
    
    def generate_bucket_names(self):
        bucket_names = set()
        for word in self.wordlist:
            bucket_names.add(word)
            bucket_names.add(f"{word}-prod")
            bucket_names.add(f"{word}-dev")
            bucket_names.add(f"{word}-test")
            bucket_names.add(f"my-{word}")
            bucket_names.add(f"{word}-bucket")
        
        for prefix in self.prefixes:
            bucket_names.add(prefix)
            bucket_names.add(f"{prefix}-backup")
            bucket_names.add(f"{prefix}-data")
            bucket_names.add(f"{prefix}-files")
            bucket_names.add(f"{prefix}-uploads")
            bucket_names.add(f"{prefix}-public")
            bucket_names.add(f"{prefix}-private")
            bucket_names.add(f"{prefix}-assets")
            bucket_names.add(f"{prefix}-static")
            bucket_names.add(f"{prefix}-media")
            bucket_names.add(f"{prefix}-logs")
            bucket_names.add(f"{prefix}-config")
            bucket_names.add(f"{prefix}-temp")
            bucket_names.add(f"{prefix}-prod")
            bucket_names.add(f"{prefix}-dev")
            bucket_names.add(f"{prefix}-test")
            bucket_names.add(f"{prefix}-staging")
            bucket_names.add(f"{prefix}data")
            bucket_names.add(f"{prefix}files")
            bucket_names.add(f"{prefix}backup")
            bucket_names.add(f"{prefix}uploads")
            bucket_names.add(f"com.{prefix}")
            bucket_names.add(f"net.{prefix}")
            bucket_names.add(f"org.{prefix}")
            bucket_names.add(f"{prefix}.com")
            bucket_names.add(f"{prefix}.net")
            bucket_names.add(f"{prefix}.org")
        
        return list(bucket_names)
    
    def rate_limit_wait(self):
        if self.rate_limit > 0:
            time.sleep(1.0 / self.rate_limit)
    
    def test_bucket_public(self, bucket_name):
        self.rate_limit_wait()
        with self.lock:
            self.request_count += 1
        
        try:
            response = self.s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
            return True, response.get('KeyCount', 0) > 0
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['AccessDenied', 'NoSuchBucket', 'InvalidBucketName']:
                return False, False
            return False, False
        except Exception:
            return False, False
    
    def list_bucket_contents(self, bucket_name, max_keys=100):
        self.rate_limit_wait()
        with self.lock:
            self.request_count += 1
        
        try:
            response = self.s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=max_keys)
            contents = []
            if 'Contents' in response:
                for obj in response['Contents']:
                    contents.append({
                        'key': obj['Key'],
                        'size': obj['Size'],
                        'last_modified': obj['LastModified'].isoformat() if obj.get('LastModified') else 'N/A',
                    })
            return contents
        except Exception:
            return []
    
    def is_sensitive_file(self, filename):
        for pattern in SENSITIVE_PATTERNS:
            if re.search(pattern, filename, re.IGNORECASE):
                return True
        return False
    
    def scan_bucket(self, bucket_name):
        print(f"{Colors.DIM}[*] Testing: {bucket_name}{Colors.ENDC}")
        
        is_public, has_objects = self.test_bucket_public(bucket_name)
        if not is_public:
            return
        
        print(f"{Colors.FAIL}[!] PUBLIC BUCKET FOUND: {bucket_name}{Colors.ENDC}")
        
        contents = self.list_bucket_contents(bucket_name)
        
        bucket_finding = {
            'bucket': bucket_name,
            'is_public': True,
            'has_objects': has_objects,
            'object_count': len(contents),
            'objects': [],
            'sensitive_files': []
        }
        
        with self.lock:
            self.public_buckets.append(bucket_name)
        
        for obj in contents:
            if self.is_sensitive_file(obj['key']):
                obj['is_sensitive'] = True
                bucket_finding['sensitive_files'].append(obj)
                with self.lock:
                    self.sensitive_files.append({
                        'bucket': bucket_name,
                        'key': obj['key'],
                        'size': obj['size'],
                        'last_modified': obj['last_modified']
                    })
                print(f"{Colors.WARNING}[!] SENSITIVE FILE: {bucket_name}/{obj['key']}{Colors.ENDC}")
            else:
                obj['is_sensitive'] = False
            bucket_finding['objects'].append(obj)
            if len(bucket_finding['objects']) >= 100:
                break
        
        with self.lock:
            self.findings.append(bucket_finding)
    
    def run_scan(self):
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}  PROJECT #32 — AWS S3 Bucket Scanner{Colors.ENDC}")
        print(f"{Colors.OKBLUE}  Enumerating and scanning public S3 buckets{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        print(f"{Colors.RED}⚠️⚠️⚠️  ETHICAL WARNING  ⚠️⚠️⚠️{Colors.ENDC}")
        print(f"{Colors.YELLOW}Only scan buckets you own or have permission to test.{Colors.ENDC}\n")
        
        if not BOTO3_AVAILABLE:
            print(f"{Colors.FAIL}[-] boto3 not available{Colors.ENDC}")
            return
        
        if not self.connect():
            print(f"{Colors.FAIL}[-] Failed to connect to AWS{Colors.ENDC}")
            return
        
        bucket_names = self.generate_bucket_names()
        print(f"{Colors.OKGREEN}[+] Generated {len(bucket_names)} bucket names to test{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Rate limit: {self.rate_limit} req/s{Colors.ENDC}\n")
        
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.scan_bucket, name): name for name in bucket_names}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"{Colors.FAIL}[-] Error: {e}{Colors.ENDC}")
        
        elapsed = time.time() - start_time
        self.print_summary(elapsed)
        self.generate_report()
    
    def print_summary(self, elapsed):
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}  SCAN SUMMARY{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Buckets tested: {len(self.generate_bucket_names())}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] API requests: {self.request_count}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Time elapsed: {elapsed:.2f}s{Colors.ENDC}")
        print(f"{Colors.FAIL}[+] Public buckets found: {len(self.public_buckets)}{Colors.ENDC}")
        print(f"{Colors.WARNING}[+] Sensitive files found: {len(self.sensitive_files)}{Colors.ENDC}")
        
        if self.public_buckets:
            print(f"\n{Colors.FAIL}Public buckets:{Colors.ENDC}")
            for bucket in self.public_buckets[:10]:
                print(f"  {Colors.FAIL}• {bucket}{Colors.ENDC}")
        
        if self.sensitive_files:
            print(f"\n{Colors.WARNING}Sensitive files:{Colors.ENDC}")
            for file in self.sensitive_files[:10]:
                print(f"  {Colors.WARNING}• {file['bucket']}/{file['key']} ({file['size']} bytes){Colors.ENDC}")
        
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
    
    def generate_report(self):
        print(f"{Colors.OKBLUE}[*] Generating HTML report...{Colors.ENDC}")
        
        html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>S3 Bucket Scanner Report</title>
<style>
body{{font-family:'Segoe UI',sans-serif;background:#1a1a2e;color:#e0e0e0;padding:20px;}}
.container{{max-width:1200px;margin:0 auto;}}
.header{{background:linear-gradient(135deg,#16213e,#0f3460);padding:30px;border-radius:10px;}}
.header h1{{color:#00d4ff;}}
.header .warning{{color:#ff4444;font-weight:bold;}}
.stats{{display:flex;gap:20px;margin:20px 0;flex-wrap:wrap;}}
.stat-box{{flex:1;min-width:120px;padding:20px;border-radius:8px;text-align:center;}}
.stat-total{{background:#1a1a3e;}}
.stat-public{{background:#ff0040;}}
.stat-sensitive{{background:#ffa500;}}
.stat-box .number{{font-size:32px;font-weight:bold;}}
.stat-box .label{{font-size:12px;color:#888;}}
.bucket{{background:#2d2d44;padding:15px;margin:10px 0;border-radius:8px;border-left:4px solid #ff0040;}}
.bucket .name{{color:#00d4ff;font-weight:bold;}}
.file{{background:#1a1a3e;padding:8px;margin:3px 0;border-radius:4px;font-family:monospace;font-size:12px;}}
.file.sensitive{{border-left:3px solid #ffa500;}}
.defense{{background:#0f3460;padding:15px;border-radius:8px;margin-top:20px;}}
.defense h3{{color:#00d4ff;}}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>☁️ AWS S3 Bucket Scanner Report</h1>
<p class="warning">⚠️ EDUCATIONAL USE ONLY ⚠️</p>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p>Total Buckets Tested: {len(self.generate_bucket_names())}</p>
<p>Public Buckets Found: {len(self.public_buckets)}</p>
<p>Sensitive Files Found: {len(self.sensitive_files)}</p>
</div>
<div class="stats">
<div class="stat-box stat-total"><div class="number">{len(self.generate_bucket_names())}</div><div class="label">Buckets Tested</div></div>
<div class="stat-box stat-public"><div class="number">{len(self.public_buckets)}</div><div class="label">Public Buckets</div></div>
<div class="stat-box stat-sensitive"><div class="number">{len(self.sensitive_files)}</div><div class="label">Sensitive Files</div></div>
</div>
<div style="margin:20px 0;">
<h2 style="color:#00d4ff;">📋 Public Buckets</h2>"""
        
        if not self.public_buckets:
            html += '<p style="color:#888;">No public buckets found.</p>'
        else:
            for finding in self.findings:
                html += f"""
<div class="bucket">
<div class="name">📦 {finding['bucket']}</div>
<div style="font-size:12px;color:#888;">Objects: {finding['object_count']} | Sensitive: {len(finding['sensitive_files'])}</div>"""
                
                if finding['sensitive_files']:
                    html += '<div style="margin-top:5px;"><strong style="color:#ffa500;">Sensitive Files:</strong></div>'
                    for file in finding['sensitive_files'][:20]:
                        html += f"""
<div class="file sensitive">🔴 {file['key']} ({file['size']} bytes)</div>"""
                
                if finding['objects']:
                    html += '<details><summary style="cursor:pointer;color:#00d4ff;margin-top:5px;">Show all objects</summary>'
                    for obj in finding['objects'][:50]:
                        html += f"""
<div class="file">{obj['key']} ({obj['size']} bytes)</div>"""
                    if len(finding['objects']) > 50:
                        html += f'<div style="color:#888;">... and {len(finding["objects"])-50} more</div>'
                    html += '</details>'
                html += '</div>'
        
        html += """
</div>
<div class="defense">
<h3>🛡️ Defenses Against S3 Bucket Enumeration</h3>
<table style="width:100%;border-collapse:collapse;">
<tr><th style="text-align:left;color:#00d4ff;">Defense</th><th style="text-align:left;color:#00d4ff;">Description</th></tr>
<tr><td>Random Bucket Names</td><td>Use random names instead of predictable patterns</td></tr>
<tr><td>Block Public Access</td><td>Enable "Block all public access" by default</td></tr>
<tr><td>Bucket Policies</td><td>Use strict policies with conditions</td></tr>
<tr><td>Logging</td><td>Enable S3 access logging</td></tr>
<tr><td>AWS Config</td><td>Monitor bucket configurations</td></tr>
</table>
</div>
<div style="text-align:center;color:#666;margin-top:30px;font-size:12px;">
<p>Generated by S3 Bucket Scanner | 100 Ethical Hacking Projects</p>
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
    parser = argparse.ArgumentParser(description="AWS S3 Bucket Scanner")
    parser.add_argument("--prefix", action="append", help="Company prefix")
    parser.add_argument("--wordlist", help="Wordlist file")
    parser.add_argument("--rate-limit", type=int, default=10, help="Requests per second")
    parser.add_argument("--threads", type=int, default=20, help="Max threads")
    parser.add_argument("--output", default="s3_report.html", help="HTML report file")
    
    args = parser.parse_args()
    
    wordlist = DEFAULT_WORDLIST
    if args.wordlist and os.path.exists(args.wordlist):
        try:
            with open(args.wordlist, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            print(f"{Colors.OKGREEN}[+] Loaded {len(wordlist)} words from {args.wordlist}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.WARNING}[!] Failed to load wordlist: {e}{Colors.ENDC}")
    
    scanner = S3Scanner(
        prefixes=args.prefix or [],
        wordlist=wordlist,
        rate_limit=args.rate_limit,
        max_threads=args.threads,
        output_file=args.output
    )
    
    scanner.run_scan()

if __name__ == "__main__":
    main()