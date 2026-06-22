#!/usr/bin/env python3
"""
============================================================
  PROJECT #6 — Web Crawler & Directory Brute Forcer
  100 Ethical Hacking Projects Series
  Libs    : requests, BeautifulSoup4, urllib.parse
  Threads : max 10 concurrent workers
  Depth   : 2 levels deep crawl
============================================================

  ╔══════════════════════════════════════════════════════╗
  ║          ⚠  ETHICAL USE WARNING  ⚠                  ║
  ║  Scan ONLY targets you own or have permission to     ║
  ║  test. Legal targets: testphp.vulnweb.com,           ║
  ║  hackthebox machines, your own lab servers.          ║
  ╚══════════════════════════════════════════════════════╝

REAL-WORLD RED TEAM USE CASE
------------------------------
Reconnaissance phase: before any exploit, a pentester maps
the attack surface. Web crawling finds hidden admin panels,
backup files (.zip/.sql), exposed git repos (.git/config),
and dev leftovers (phpinfo.php, test.php). Each 200/403 hit
is a potential entry point or information leak. Combined
with Burp Suite or nikto, this is step 1 of every web app
pentest — finding what the server accidentally exposes.

DETECTION BY BLUE TEAM
------------------------
WAF / IDS logs spike of 50+ 404s from single IP in < 10s
= classic brute force signature. Defense: rate-limit to
30 req/min per IP, alert on >20 consecutive 404s, deploy
honeypot paths that log + block any IP that hits them.

USAGE
------
  python3 project6_crawler.py --url http://testphp.vulnweb.com
  python3 project6_crawler.py --url http://target.com --depth 2 --delay 0.5
  python3 project6_crawler.py --url http://target.com --no-robots
  python3 project6_crawler.py --url http://target.com --wordlist mylist.txt
============================================================
"""

import argparse
import sys
import time
import threading
import urllib.parse
import urllib.robotparser
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup

# ── colours ───────────────────────────────────────────────
R="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
YELLOW="\033[93m";CYAN="\033[96m";MAGENTA="\033[95m";DIM="\033[2m"
BLUE="\033[94m"
def c(t,code): return f"{code}{t}{R}"

# ── built-in wordlist (60 common endpoints) ───────────────
WORDLIST = [
    # admin / control panels
    "admin", "admin/", "administrator", "admin.php", "admin.html",
    "wp-admin", "wp-admin/", "wp-login.php", "cpanel", "phpmyadmin",
    "dashboard", "manager", "panel", "controlpanel", "backend",
    # config / sensitive files
    ".git/config", ".git/HEAD", ".env", ".htaccess", ".htpasswd",
    "config.php", "config.yml", "config.json", "database.yml",
    "settings.php", "wp-config.php", "web.config", "server.xml",
    # info / debug
    "phpinfo.php", "info.php", "test.php", "debug.php", "status",
    "server-status", "server-info", "robots.txt", "sitemap.xml",
    "crossdomain.xml", "clientaccesspolicy.xml",
    # backup / dump files
    "backup.zip", "backup.sql", "backup.tar.gz", "db.sql", "dump.sql",
    "database.sql", "backup/", "old/", "bak/", "archive/",
    # common dirs
    "upload", "uploads", "upload/", "uploads/", "images/", "img/",
    "static/", "assets/", "css/", "js/", "files/", "documents/",
    "api/", "api/v1/", "api/v2/", "rest/", "graphql",
    # login / auth
    "login", "login.php", "logout", "register", "signup",
    "user", "users", "account", "profile",
]

# ── status → colour ───────────────────────────────────────
STATUS_COLOR = {
    200: GREEN, 201: GREEN, 204: GREEN,
    301: YELLOW, 302: YELLOW, 307: YELLOW, 308: YELLOW,
    400: DIM,   401: MAGENTA, 403: YELLOW,
    404: DIM,   500: RED,    503: RED,
}
def status_c(code):
    return c(str(code), STATUS_COLOR.get(code, DIM))

# ─────────────────────────────────────────────────────────
# ROBOTS.TXT PARSER
# ─────────────────────────────────────────────────────────
def load_robots(base_url: str, session: requests.Session) -> urllib.robotparser.RobotFileParser:
    rp = urllib.robotparser.RobotFileParser()
    robots_url = base_url.rstrip("/") + "/robots.txt"
    try:
        resp = session.get(robots_url, timeout=5)
        rp.parse(resp.text.splitlines())
        print(c(f"  [robots.txt] Loaded from {robots_url}", DIM))
        # show a preview
        for line in resp.text.splitlines()[:8]:
            if line.strip():
                print(c(f"    {line}", DIM))
    except Exception:
        print(c(f"  [robots.txt] Not found or unreachable — continuing.", DIM))
    rp.set_url(robots_url)
    return rp

# ─────────────────────────────────────────────────────────
# LINK EXTRACTOR
# ─────────────────────────────────────────────────────────
def extract_links(html: str, base_url: str, target_netloc: str) -> set:
    """Parse HTML, return set of absolute internal links."""
    soup  = BeautifulSoup(html, "html.parser")
    links = set()
    for tag in soup.find_all(["a", "link", "form"], href=True):
        href = tag.get("href") or tag.get("action", "")
        if not href:
            continue
        abs_url = urllib.parse.urljoin(base_url, href)
        parsed  = urllib.parse.urlparse(abs_url)
        # internal only, strip fragment, http/https only
        if parsed.netloc == target_netloc and parsed.scheme in ("http","https"):
            clean = parsed._replace(fragment="").geturl()
            links.add(clean)
    # also grab form actions
    for form in soup.find_all("form"):
        action = form.get("action", "")
        if action:
            abs_url = urllib.parse.urljoin(base_url, action)
            parsed  = urllib.parse.urlparse(abs_url)
            if parsed.netloc == target_netloc:
                links.add(parsed._replace(fragment="").geturl())
    return links

# ─────────────────────────────────────────────────────────
# CRAWLER
# ─────────────────────────────────────────────────────────
def crawl(start_url: str, max_depth: int, session: requests.Session,
          rp, respect_robots: bool, delay: float) -> dict:
    """
    BFS crawl up to max_depth.
    Returns {url: {"status": int, "links": set}}.
    """
    parsed_start = urllib.parse.urlparse(start_url)
    target_netloc = parsed_start.netloc

    visited = {}     # url → {status, links}
    queue   = deque([(start_url, 0)])   # (url, depth)
    seen    = {start_url}
    lock    = threading.Lock()

    print(c(f"\n  ── CRAWL PHASE (depth={max_depth}) ─────────────────────────────", CYAN))
    print(f"  {'DEPTH':<7} {'STATUS':<8} URL")
    print("  " + "─"*70)

    while queue:
        url, depth = queue.popleft()

        if depth > max_depth:
            continue

        if respect_robots and not rp.can_fetch("*", url):
            print(f"  {c('  skip', DIM)}   {c('robots', DIM):<8} {c(url, DIM)}")
            continue

        try:
            resp = session.get(url, timeout=8, allow_redirects=True)
            status = resp.status_code
        except Exception as e:
            print(f"  {'?':<7} {c('ERR', RED):<8} {url}  ({e})")
            continue

        links = set()
        if status == 200 and "text/html" in resp.headers.get("content-type",""):
            links = extract_links(resp.text, url, target_netloc)

        visited[url] = {"status": status, "links": links, "depth": depth}
        depth_label = c(f"  d={depth}", MAGENTA)
        print(f"  {depth_label:<14} {status_c(status):<20} {url}")

        if depth < max_depth:
            with lock:
                for link in links:
                    if link not in seen:
                        seen.add(link)
                        queue.append((link, depth + 1))

        time.sleep(delay)

    return visited

# ─────────────────────────────────────────────────────────
# BRUTE FORCER
# ─────────────────────────────────────────────────────────
def brute_force_url(args):
    """Worker fn: probe one url, return (url, status_code)."""
    url, session, delay = args
    try:
        resp = session.get(url, timeout=6, allow_redirects=False)
        time.sleep(delay)
        return url, resp.status_code
    except Exception:
        return url, None

def brute_force(base_urls: list, wordlist: list, session: requests.Session,
                workers: int, delay: float) -> dict:
    """
    For each base_url × each word → probe URL.
    Returns {url: status_code} for non-404 hits.
    """
    print(c(f"\n  ── BRUTE FORCE PHASE ({len(base_urls)} bases × {len(wordlist)} words) ─────", CYAN))
    print(f"  {'STATUS':<8} URL")
    print("  " + "─"*70)

    tasks = []
    for base in base_urls:
        for word in wordlist:
            url = base.rstrip("/") + "/" + word.lstrip("/")
            tasks.append((url, session, delay))

    hits   = {}
    total  = len(tasks)
    done   = [0]
    p_lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=workers) as exe:
        futures = {exe.submit(brute_force_url, t): t for t in tasks}
        for future in as_completed(futures):
            url, status = future.result()
            with p_lock:
                done[0] += 1
                pct = done[0] / total
                bar = "█" * int(pct * 25) + "░" * (25 - int(pct * 25))
                print(f"\r  {c(bar, CYAN)}  {done[0]}/{total}", end="", flush=True)

            if status and status != 404:
                hits[url] = status

    print()  # newline after progress bar

    # print hits sorted by status
    for url, status in sorted(hits.items(), key=lambda x: x[1]):
        icon = "✔" if status == 200 else "⚠" if status in (301,302,403) else "?"
        print(f"  {c(icon, GREEN if status==200 else YELLOW)}"
              f"  {status_c(status):<20} {url}")

    return hits

# ─────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────
def print_summary(crawl_results: dict, brute_hits: dict, elapsed: float):
    print(c(f"\n  ── SUMMARY ──────────────────────────────────────────────", CYAN))

    # crawl stats
    status_counts = {}
    for v in crawl_results.values():
        s = v["status"]
        status_counts[s] = status_counts.get(s, 0) + 1

    print(f"\n  {c('CRAWL', BOLD)}  ({len(crawl_results)} pages)")
    for s in sorted(status_counts):
        print(f"    HTTP {status_c(s)} : {status_counts[s]} page(s)")

    # brute force stats
    bf_by_status = {}
    for url, s in brute_hits.items():
        bf_by_status.setdefault(s, []).append(url)

    print(f"\n  {c('BRUTE FORCE', BOLD)}  ({len(brute_hits)} hits out of non-404 responses)")
    if brute_hits:
        for s in sorted(bf_by_status):
            print(f"\n    {c('HTTP ' + str(s), STATUS_COLOR.get(s, DIM))} ({len(bf_by_status[s])} hits)")
            for url in sorted(bf_by_status[s]):
                print(f"      {url}")
    else:
        print(c("    No hits (all 404 or unreachable).", DIM))

    print(f"\n  {c('Total time:', DIM)} {elapsed:.1f}s")
    print()

# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Project #6 — Web Crawler & Dir Brute Forcer")
    parser.add_argument("--url",        required=True,          help="Start URL (e.g. http://testphp.vulnweb.com)")
    parser.add_argument("--depth",      type=int, default=2,    help="Crawl depth (default: 2)")
    parser.add_argument("--delay",      type=float, default=0.2,help="Delay between requests in seconds (default: 0.2)")
    parser.add_argument("--workers",    type=int, default=10,   help="Brute force thread workers (default: 10)")
    parser.add_argument("--no-robots",  action="store_true",    help="Ignore robots.txt")
    parser.add_argument("--wordlist",   default=None,           help="Path to custom wordlist file (one entry per line)")
    parser.add_argument("--brute-only", action="store_true",    help="Skip crawl, brute force base URL only")
    args = parser.parse_args()

    # normalise URL
    if not args.url.startswith("http"):
        args.url = "http://" + args.url
    parsed = urllib.parse.urlparse(args.url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # load wordlist
    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                wordlist = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except FileNotFoundError:
            print(c(f"\n  [ERROR] Wordlist not found: {args.wordlist}\n", RED))
            sys.exit(1)
    else:
        wordlist = WORDLIST

    # HTTP session with user-agent
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; EthicalScanner/1.0; +educational)",
        "Accept"    : "text/html,application/xhtml+xml,*/*",
    })

    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   PROJECT #6 · WEB CRAWLER & DIR BRUTE FORCER        ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════════╝", CYAN))
    print()
    print(c("  ⚠  Authorised targets only.", RED))
    print()
    print(f"  Target   : {c(args.url, YELLOW)}")
    print(f"  Depth    : {args.depth}    Workers: {args.workers}    Delay: {args.delay}s")
    print(f"  Wordlist : {len(wordlist)} entries")
    print(f"  Robots   : {'respect' if not args.no_robots else c('IGNORED', RED)}")

    t_start = time.time()

    # load robots
    rp = load_robots(base_url, session) if not args.no_robots else urllib.robotparser.RobotFileParser()

    # crawl
    crawl_results = {}
    if not args.brute_only:
        crawl_results = crawl(args.url, args.depth, session, rp,
                              not args.no_robots, args.delay)

    # collect unique base paths for brute forcing
    # use base_url + each unique path prefix from crawled pages
    brute_bases = {base_url}
    for url in crawl_results:
        p = urllib.parse.urlparse(url)
        path_parts = p.path.rsplit("/", 1)
        if len(path_parts) > 1 and path_parts[0]:
            brute_bases.add(f"{p.scheme}://{p.netloc}{path_parts[0]}")
    brute_bases = sorted(brute_bases)

    print(f"\n  Brute force bases ({len(brute_bases)}): "
          + "  ".join(c(b, MAGENTA) for b in brute_bases[:5]))

    # brute force
    brute_hits = brute_force(brute_bases, wordlist, session, args.workers, args.delay)

    elapsed = time.time() - t_start
    print_summary(crawl_results, brute_hits, elapsed)


if __name__ == "__main__":
    main()