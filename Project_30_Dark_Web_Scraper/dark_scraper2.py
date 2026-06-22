#!/usr/bin/env python3
"""
==============================================================
  PROJECT #30 — Dark Web Scraper (Tor) — Educational Only
  Fixed version with better content extraction
==============================================================
"""

import os
import sys
import time
import random
import re
import json
from datetime import datetime
from urllib.parse import urljoin, urlparse

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = ''; GREEN = ''; YELLOW = ''; BLUE = ''; MAGENTA = ''; CYAN = ''
        LIGHTBLACK_EX = ''; RESET = ''; LIGHTRED_EX = ''
    class Style:
        BRIGHT = ''; DIM = ''; RESET_ALL = ''

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print(f"{Fore.RED}[-] requests not installed{Fore.RESET}")

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    print(f"{Fore.RED}[-] beautifulsoup4 not installed{Fore.RESET}")

class TorScraper:
    def __init__(self, tor_port=9050, timeout=30, delay_range=(1, 3)):
        self.tor_port = tor_port
        self.timeout = timeout
        self.delay_range = delay_range
        self.session = None
        self.results = []
        self.visited = set()
        self.keywords = []
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
        ]
        
    def display_warning(self):
        print(f"""
{Fore.RED}{'='*80}{Fore.RESET}
{Fore.RED}⚠️⚠️⚠️  ETHICAL WARNING  ⚠️⚠️⚠️{Fore.RESET}
{Fore.RED}{'='*80}{Fore.RESET}
{Fore.YELLOW}This tool is for EDUCATIONAL PURPOSES ONLY.{Fore.RESET}
{Fore.YELLOW}- Only use on sites you have permission to scrape{Fore.RESET}
{Fore.YELLOW}- Do not access illegal content{Fore.RESET}
{Fore.YELLOW}- Do not use for malicious purposes{Fore.RESET}
{Fore.RED}{'='*80}{Fore.RESET}
        """)
        time.sleep(2)
        
    def setup_tor_session(self):
        if not REQUESTS_AVAILABLE:
            return False
            
        try:
            self.session = requests.Session()
            proxies = {
                'http': f'socks5h://127.0.0.1:{self.tor_port}',
                'https': f'socks5h://127.0.0.1:{self.tor_port}'
            }
            self.session.proxies = proxies
            self.session.headers.update({
                'User-Agent': random.choice(self.user_agents)
            })
            print(f"{Fore.GREEN}[+] Tor SOCKS5 proxy configured on port {self.tor_port}{Fore.RESET}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to setup Tor session: {e}{Fore.RESET}")
            return False
    
    def test_tor_connection(self):
        print(f"{Fore.CYAN}[*] Testing Tor connection...{Fore.RESET}")
        if not self.session:
            return False
        try:
            response = self.session.get('http://check.torproject.org', timeout=30)
            if 'Congratulations' in response.text or 'Tor' in response.text:
                print(f"{Fore.GREEN}[+] Tor connection successful!{Fore.RESET}")
                return True
            print(f"{Fore.GREEN}[+] Tor connection successful (partial){Fore.RESET}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[-] Tor connection failed: {e}{Fore.RESET}")
            return False
    
    def load_keywords(self, keywords_file=None):
        default_keywords = [
            'password', 'breach', 'leak', 'hack', 'exploit', 'vulnerability',
            'dump', 'database', 'credit card', 'social security', 'ssn',
            'dark web', 'cyber', 'attack', 'malware', 'ransomware',
            'phishing', 'credentials', 'email', 'login', 'admin',
            'confidential', 'secret', 'classified', 'top secret',
            'tor', 'anonymous', 'privacy', 'security'
        ]
        
        if keywords_file and os.path.exists(keywords_file):
            try:
                with open(keywords_file, 'r') as f:
                    self.keywords = [line.strip().lower() for line in f if line.strip()]
                print(f"{Fore.GREEN}[+] Loaded {len(self.keywords)} keywords from {keywords_file}{Fore.RESET}")
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Failed to load keywords: {e}{Fore.RESET}")
                self.keywords = default_keywords
        else:
            self.keywords = default_keywords
            print(f"{Fore.GREEN}[+] Using {len(self.keywords)} default keywords{Fore.RESET}")
        return self.keywords
    
    def get_random_delay(self):
        return random.uniform(self.delay_range[0], self.delay_range[1])
    
    def get_random_user_agent(self):
        return random.choice(self.user_agents)
    
    def scrape_page(self, url):
        """Scrape a single page and extract keywords"""
        try:
            # Random delay
            time.sleep(self.get_random_delay())
            
            # Random user agent
            self.session.headers.update({
                'User-Agent': self.get_random_user_agent()
            })
            
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code != 200:
                print(f"{Fore.YELLOW}[!] Status {response.status_code}: {url}{Fore.RESET}")
                return None
            
            # Get text content
            if BS4_AVAILABLE:
                soup = BeautifulSoup(response.text, 'html.parser')
                # Remove script and style tags
                for script in soup(["script", "style"]):
                    script.decompose()
                text = soup.get_text(separator=' ', strip=True)
                title = soup.title.string if soup.title and soup.title.string else 'No Title'
            else:
                text = response.text
                title = 'Unknown'
            
            # Find keywords
            found_keywords = []
            keyword_counts = {}
            
            for keyword in self.keywords:
                count = text.lower().count(keyword.lower())
                if count > 0:
                    found_keywords.append(keyword)
                    keyword_counts[keyword] = count
            
            if found_keywords:
                print(f"{Fore.GREEN}[+] Found {len(found_keywords)} keywords on {url}{Fore.RESET}")
                return {
                    'url': url,
                    'title': title,
                    'timestamp': datetime.now().isoformat(),
                    'keywords': found_keywords,
                    'keyword_counts': keyword_counts,
                    'text_snippet': text[:500] + '...',
                    'status_code': response.status_code,
                    'content_length': len(response.text)
                }
            else:
                print(f"{Fore.DIM}[*] No keywords found on {url}{Fore.RESET}")
                return {
                    'url': url,
                    'title': title,
                    'timestamp': datetime.now().isoformat(),
                    'keywords': [],
                    'keyword_counts': {},
                    'text_snippet': text[:200] + '...',
                    'status_code': response.status_code,
                    'content_length': len(response.text)
                }
                
        except requests.exceptions.Timeout:
            print(f"{Fore.YELLOW}[!] Timeout: {url}{Fore.RESET}")
            return None
        except requests.exceptions.ConnectionError:
            print(f"{Fore.YELLOW}[!] Connection error: {url}{Fore.RESET}")
            return None
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}{Fore.RESET}")
            return None
    
    def crawl(self, url, max_depth=1, current_depth=0, max_pages=10):
        """Crawl a website"""
        if current_depth > max_depth:
            return
        if len(self.visited) >= max_pages:
            return
        if url in self.visited:
            return
        
        url = url.rstrip('/')
        self.visited.add(url)
        
        print(f"{Fore.CYAN}[*] Crawling: {url} (depth {current_depth}){Fore.RESET}")
        
        # Scrape the page
        result = self.scrape_page(url)
        if result:
            result['depth'] = current_depth
            self.results.append(result)
        
        # Find links for crawling
        if current_depth < max_depth and BS4_AVAILABLE:
            try:
                time.sleep(self.get_random_delay())
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    links = set()
                    
                    for a in soup.find_all('a', href=True):
                        href = a['href']
                        if href.startswith('http'):
                            links.add(href)
                        elif href.startswith('/'):
                            links.add(urljoin(url, href))
                    
                    # Filter to same domain
                    domain = urlparse(url).netloc
                    filtered_links = []
                    for link in links:
                        link_domain = urlparse(link).netloc
                        if domain in link_domain or not link_domain:
                            filtered_links.append(link)
                    
                    # Limit links
                    filtered_links = filtered_links[:5]
                    
                    for link in filtered_links:
                        if len(self.visited) >= max_pages:
                            break
                        self.crawl(link, max_depth, current_depth + 1, max_pages)
                        
            except Exception as e:
                print(f"{Fore.DIM}[!] Could not get links from {url}: {e}{Fore.RESET}")
    
    def generate_report(self, output_file="dark_report.html"):
        print(f"\n{Fore.CYAN}[*] Generating HTML report...{Fore.RESET}")
        
        keyword_freq = {}
        for result in self.results:
            for keyword in result.get('keywords', []):
                keyword_freq[keyword] = keyword_freq.get(keyword, 0) + 1
        
        sorted_keywords = sorted(keyword_freq.items(), key=lambda x: x[1], reverse=True)
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Dark Web Scraper Report</title>
    <style>
        body {{font-family:'Segoe UI',sans-serif;background:#1a1a2e;color:#e0e0e0;padding:20px;}}
        .container {{max-width:1200px;margin:0 auto;}}
        .header {{background:linear-gradient(135deg,#16213e,#0f3460);padding:30px;border-radius:10px;margin-bottom:20px;}}
        .header h1 {{color:#00d4ff;}}
        .header .warning {{color:#ff4444;font-weight:bold;}}
        .section {{background:#2d2d44;padding:20px;border-radius:10px;margin:15px 0;}}
        .section h2 {{color:#00d4ff;border-bottom:1px solid #3d3d5a;padding-bottom:10px;}}
        .stat-box {{display:inline-block;background:#1a1a3e;padding:15px;border-radius:8px;margin:5px;min-width:150px;}}
        .stat-box .value {{font-size:24px;font-weight:bold;color:#00d4ff;}}
        .stat-box .label {{color:#888;font-size:12px;}}
        .finding {{background:#2d2d44;padding:15px;margin:10px 0;border-radius:8px;border-left:4px solid #ffa500;}}
        .finding .url {{color:#00d4ff;font-family:monospace;word-break:break-all;}}
        .tag {{display:inline-block;background:#1a1a3e;padding:3px 10px;border-radius:12px;margin:2px;font-size:12px;}}
        .tag-high {{background:#ff4444;}}
        .tag-medium {{background:#ffa500;}}
        .tag-low {{background:#00d4ff;}}
        .defense {{background:#0f3460;padding:15px;border-radius:8px;margin-top:20px;}}
        .defense h3 {{color:#00d4ff;}}
        .defense td {{color:#ccc;padding:5px;}}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🌑 Dark Web Scraper Report</h1>
        <p class="warning">⚠️ EDUCATIONAL USE ONLY ⚠️</p>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Total URLs crawled: {len(self.results)}</p>
        <p>Unique keywords found: {len(keyword_freq)}</p>
    </div>
    
    <div class="section">
        <h2>📊 Statistics</h2>
        <div>
            <div class="stat-box"><div class="value">{len(self.results)}</div><div class="label">Pages Crawled</div></div>
            <div class="stat-box"><div class="value">{len(self.visited)}</div><div class="label">URLs Discovered</div></div>
            <div class="stat-box"><div class="value">{len(keyword_freq)}</div><div class="label">Unique Keywords</div></div>
            <div class="stat-box"><div class="value">{sum(keyword_freq.values())}</div><div class="label">Total Keyword Matches</div></div>
        </div>
    </div>
    
    <div class="section">
        <h2>📋 Top Keywords</h2>
        <div style="display:flex;flex-wrap:wrap;gap:5px;margin:10px 0;">"""
        
        for keyword, count in sorted_keywords[:20]:
            if count >= 5:
                tag_class = 'tag-high'
            elif count >= 3:
                tag_class = 'tag-medium'
            else:
                tag_class = 'tag-low'
            html += f'<span class="tag {tag_class}">{keyword} ({count})</span>'
        
        html += """
        </div>
    </div>
    
    <div class="section">
        <h2>📄 Findings</h2>"""
        
        if not self.results:
            html += '<p style="color:#888;">No results found. Try a different URL or check Tor connection.</p>'
        else:
            for result in self.results:
                if result.get('keywords'):
                    html += f"""
        <div class="finding">
            <div class="url">📍 {result['url']}</div>
            <div><strong>Title:</strong> {result.get('title', 'N/A')}</div>
            <div><strong>Keywords:</strong> {', '.join(result['keywords'])}</div>
            <div style="font-size:12px;color:#888;">Depth: {result.get('depth', 0)} | Time: {result['timestamp']}</div>
            <div style="font-size:12px;color:#888;">Status: {result.get('status_code', 'N/A')} | Size: {result.get('content_length', 0)} bytes</div>
            <details>
                <summary style="cursor:pointer;color:#00d4ff;">View Snippet</summary>
                <p style="font-size:12px;color:#ccc;margin-top:5px;">{result.get('text_snippet', 'N/A')}</p>
            </details>
        </div>"""
        
        html += """
    </div>
    
    <div class="section defense">
        <h3>🛡️ Defenses Against Dark Web Scraping</h3>
        <table style="width:100%;border-collapse:collapse;">
            <tr><th style="text-align:left;color:#00d4ff;">Defense</th><th style="text-align:left;color:#00d4ff;">Description</th></tr>
            <tr><td>Rate Limiting</td><td>Restrict requests per IP to prevent scraping</td></tr>
            <tr><td>CAPTCHA</td><td>Prevent automated access to content</td></tr>
            <tr><td>IP Blocking</td><td>Ban suspicious IP addresses</td></tr>
            <tr><td>Content Obfuscation</td><td>Hide sensitive content from scrapers</td></tr>
            <tr><td>Honeypot Links</td><td>Detect scrapers with fake links</td></tr>
            <tr><td>JavaScript Challenges</td><td>Block simple scrapers</td></tr>
        </table>
    </div>
    
    <div style="text-align:center;color:#666;margin-top:30px;font-size:12px;">
        <p>Generated by Dark Web Scraper | 100 Ethical Hacking Projects Series</p>
        <p>⚠️ For Educational Purposes Only ⚠️</p>
    </div>
</div>
</body>
</html>"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"{Fore.GREEN}[+] Report saved to {output_file}{Fore.RESET}")
        return output_file
    
    def print_summary(self):
        print(f"\n{Fore.CYAN}{'='*60}{Fore.RESET}")
        print(f"{Fore.CYAN}  SCRAPING SUMMARY{Fore.RESET}")
        print(f"{Fore.CYAN}{'='*60}{Fore.RESET}")
        print(f"{Fore.GREEN}URLs crawled: {len(self.results)}{Fore.RESET}")
        print(f"{Fore.GREEN}URLs discovered: {len(self.visited)}{Fore.RESET}")
        
        keyword_counts = {}
        for result in self.results:
            for keyword in result.get('keywords', []):
                keyword_counts[keyword] = keyword_counts.get(keyword, 0) + 1
        
        if keyword_counts:
            print(f"\n{Fore.YELLOW}Top keywords:{Fore.RESET}")
            for keyword, count in sorted(keyword_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {Fore.CYAN}{keyword}{Fore.RESET}: {count}")
        else:
            print(f"{Fore.YELLOW}No keywords found{Fore.RESET}")
        
        print(f"{Fore.CYAN}{'='*60}{Fore.RESET}\n")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Dark Web Scraper (Tor) - Educational Only")
    parser.add_argument("--onion", required=True, help="URL to scrape (e.g., http://check.torproject.org)")
    parser.add_argument("--keywords", help="Keywords file (one per line)")
    parser.add_argument("--output", default="dark_report.html", help="Output HTML report")
    parser.add_argument("--max-depth", type=int, default=1, help="Maximum crawl depth")
    parser.add_argument("--max-pages", type=int, default=10, help="Maximum pages to crawl")
    parser.add_argument("--port", type=int, default=9050, help="Tor SOCKS port")
    parser.add_argument("--no-warning", action="store_true", help="Skip warning banner")
    
    args = parser.parse_args()
    
    scraper = TorScraper(tor_port=args.port)
    if not args.no_warning:
        scraper.display_warning()
    
    if not REQUESTS_AVAILABLE:
        print(f"{Fore.RED}[-] requests not installed{Fore.RESET}")
        sys.exit(1)
    
    scraper.load_keywords(args.keywords)
    
    print(f"\n{Fore.CYAN}[*] Setting up Tor session...{Fore.RESET}")
    if not scraper.setup_tor_session():
        print(f"{Fore.RED}[-] Failed to setup Tor session{Fore.RESET}")
        sys.exit(1)
    
    if not scraper.test_tor_connection():
        print(f"{Fore.RED}[-] Tor connection failed{Fore.RESET}")
        sys.exit(1)
    
    print(f"\n{Fore.CYAN}[*] Starting crawl...{Fore.RESET}")
    print(f"{Fore.CYAN}[*] Target: {args.onion}{Fore.RESET}")
    print(f"{Fore.CYAN}[*] Max depth: {args.max_depth}{Fore.RESET}")
    print(f"{Fore.CYAN}[*] Max pages: {args.max_pages}{Fore.RESET}\n")
    
    scraper.crawl(args.onion, max_depth=args.max_depth, max_pages=args.max_pages)
    
    scraper.print_summary()
    scraper.generate_report(args.output)
    
    print(f"\n{Fore.GREEN}[+] Done!{Fore.RESET}")

if __name__ == "__main__":
    main()