#!/usr/bin/env python3
"""
Project #30: Dark Web Open-Source Threat Intelligence Scraper (OSINT)
Architecture: SOCKS5 Proxy Pipeline Tunneling + Heuristic Keyword Extraction.
"""

import sys
import time
import random
import argparse
from datetime import datetime

try:
    import requests
except ImportError:
    print("[-] Missing dependency: Run 'pip3 install requests[socks]'")
    sys.exit(1)

# Terminal Color Blueprints
G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"; R = "\033[91m"; BOLD = "\033[1m"; RESET = "\033[0m"

BANNER = f"""
{R}{BOLD}======================================================================
  ⚠️  ETHICAL WARNING: EDUCATIONAL THREAT INTELLIGENCE SCRAPER ONLY
  OPERATING VIA ANONYMOUS SOCKS5 PROXY MATRIX OVER THE TOR NETWORK
======================================================================{RESET}
"""

# Pool of realistic browser headers to simulate user interaction
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
]

DEFAULT_KEYWORDS = ["leak", "breach", "password", "database", "cyberaudit", "credential"]

def execute_tor_scrape(target_url: str, keyword_list: list):
    print(f"[*] Initializing outbound network circuit mapping...")
    
    # Configure the requests session framework to use the local Tor SOCKS5 daemon loop back addresses
    # Port 9050 is standard for the background system Tor service daemon
    proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }

    headers = {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
    }

    # 1. Verify Tor routing pipeline health check
    print(f"[*] Dispatching identity verification request to target: http://check.torproject.org")
    try:
        verif_res = requests.get("http://check.torproject.org", proxies=proxies, headers=headers, timeout=15)
        if "Congratulations" in verif_res.text:
            print(f"   {G}[+] Tor Circuit Alignment Confirmed! Network egress layer is masked successfully.{RESET}")
        else:
            print(f"   {Y}[!] Circuit Warning: Traffic routing through proxy, but exit node verification failed.{RESET}")
    except Exception as e:
        print(f"{R}[!] Core Network Error: Unable to communicate with local Tor SOCKS5 daemon interface -> {e}{RESET}")
        print(f"{Y}[*] Remediation: Ensure the background service is active by executing: 'sudo systemctl start tor'{RESET}")
        sys.exit(1)

    print(f"\n[*] Commencing target source collection against: {C}{target_url}{RESET}")
    print(f"[*] Active keyword indexing metrics targeting entries: {keyword_list}")
    print("-" * 75)

    # Inject variable latency timing delay to minimize profiling traces
    delay = random.uniform(1.5, 4.0)
    print(f"[*] Injecting operational anti-detection delay: {delay:.2f}s...")
    time.sleep(delay)

    try:
        response = requests.get(target_url, proxies=proxies, headers=headers, timeout=30)
        html_content = response.text.lower()
        
        print(f"   {G}[+] HTML payload extracted successfully. Size: {len(html_content)} characters.{RESET}")
        
        # 2. Heuristic Pattern Keyword Extraction Pipeline
        findings = []
        for word in keyword_list:
            occurrences = html_content.count(word.lower())
            if occurrences > 0:
                findings.append((word, occurrences))

        # 3. Report Compilation Architecture
        print(f"\n{BOLD}THREAT INTELLIGENCE EXTRACTION REPORT:{RESET}")
        print(f"┌────────────────────────────────────────────────────────────────────┐")
        print(f"│  TIMESTAMP: {datetime.now().strftime('%Y-%m-%d %H:%M:%S').ljust(54)} │")
        print(f"│  TARGET NODE: {target_url[:50].ljust(52)} │")
        print(f"└────────────────────────────────────────────────────────────────────┘")

        if findings:
            print(f"\n{R}{BOLD}⚠️  CRITICAL MATCHES LOCATED IN TARGET DATA FILE:{RESET}")
            for word, count in findings:
                print(f"  [{R}💥{RESET}] Keyword Match: '{Y}{word}{RESET}' found {BOLD}{count}{RESET} times inside raw source data.")
        else:
            print(f"\n{G}[+] Data Analysis Complete: No specified corporate intelligence risk leak indicators found.{RESET}")

    except Exception as e:
        print(f"{R}[!] Communication Failure: Target hidden node rejected data transaction flow -> {e}{RESET}")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Anonymous OSINT Intelligence Gathering Utility")
    parser.add_argument("--onion", help="Target .onion hidden service or test address url string")
    parser.add_argument("--keywords", help="Optional external file path containing target indexing terms")
    args = parser.parse_args()

    # Fallback default target checks against the secure Tor Project system confirmation page
    target_url = args.onion if args.onion else "http://check.torproject.org"
    
    keywords = DEFAULT_KEYWORDS
    if args.keywords:
        try:
            with open(args.keywords, "r") as f:
                keywords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{Y}[!] Warning: Unable to parse keyword text file configuration ({e}). Using core lists.{RESET}")

    execute_tor_scrape(target_url, keywords)

if __name__ == "__main__":
    main()
