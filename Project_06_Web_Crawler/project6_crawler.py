from __future__ import annotations

import argparse
import html
import posixpath
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup


USER_AGENT = "Project6WebCrawler/1.0 (+educational security testing)"
MAX_WORKERS = 10
DEFAULT_DEPTH = 2
DEFAULT_DELAY = 0.2
DEFAULT_TIMEOUT = 5
DEFAULT_TARGET = "http://testphp.vulnweb.com"

COMMON_ENDPOINTS = [
    "admin",
    "admin/",
    "admin.php",
    "administrator",
    "login",
    "login.php",
    "dashboard",
    "controlpanel",
    "cpanel",
    "panel",
    "private",
    "secret",
    "backup",
    "backup/",
    "backup.zip",
    "backup.tar.gz",
    "backup.sql",
    "db.sql",
    "database.sql",
    "dump.sql",
    "site.zip",
    "archive.zip",
    "uploads",
    "upload",
    "files",
    "tmp",
    "temp",
    "old",
    "old-site",
    "test",
    "dev",
    "staging",
    "assets",
    "images",
    "img",
    "css",
    "js",
    "api",
    "api/v1",
    "api/docs",
    "docs",
    "doc",
    "robots.txt",
    "sitemap.xml",
    "sitemap_index.xml",
    ".git/",
    ".git/config",
    ".gitignore",
    ".env",
    ".env.backup",
    ".env.example",
    ".htaccess",
    ".htpasswd",
    "server-status",
    "server-info",
    "phpinfo.php",
    "info.php",
    "status",
    "config.php",
    "config.inc.php",
    "config.ini",
    "web.config",
    "crossdomain.xml",
    "readme.txt",
    "README.md",
    "changelog.txt",
    "CHANGELOG.md",
    "license.txt",
    "LICENSE",
]


@dataclass(frozen=True)
class PageResult:
    url: str
    status_code: int | None
    title: str = ""
    links: tuple[str, ...] = ()
    error: str = ""


@dataclass(frozen=True)
class ProbeResult:
    base_url: str
    url: str
    status_code: int | None
    error: str = ""


class HostDelayManager:
    def __init__(self, delay_seconds: float) -> None:
        self.delay_seconds = max(0.0, delay_seconds)
        self._lock = threading.Lock()
        self._next_allowed: dict[str, float] = {}

    def wait_turn(self, host: str) -> None:
        if self.delay_seconds <= 0:
            return

        while True:
            with self._lock:
                now = time.monotonic()
                allowed_at = self._next_allowed.get(host, now)
                if allowed_at <= now:
                    self._next_allowed[host] = now + self.delay_seconds
                    return
                sleep_for = allowed_at - now
            time.sleep(sleep_for)


class Crawler:
    def __init__(self, start_url: str, max_depth: int, workers: int, timeout: float, fallback_delay: float) -> None:
        self.start_url = self._normalize_url(start_url)
        self.max_depth = max(0, max_depth)
        self.workers = max(1, min(MAX_WORKERS, workers))
        self.timeout = timeout
        self.session_factory = threading.local()
        self.delay_manager = HostDelayManager(fallback_delay)
        self._robot_lock = threading.Lock()
        self.robot_parsers: dict[str, RobotFileParser] = {}
        self.robot_delays: dict[str, float] = {}
        self.visited: set[str] = set()
        self.discovered: dict[str, PageResult] = {}
        self.probe_results: list[ProbeResult] = []

    @staticmethod
    def _normalize_url(url: str) -> str:
        parsed = urlsplit(url)
        scheme = parsed.scheme or "http"
        netloc = parsed.netloc
        path = parsed.path or "/"
        if path != "/":
            path = path.rstrip("/") or "/"
        return urlunsplit((scheme, netloc, path, parsed.query, ""))

    @staticmethod
    def _same_site(candidate_url: str, root_url: str) -> bool:
        candidate = urlsplit(candidate_url)
        root = urlsplit(root_url)
        return candidate.scheme in {"http", "https"} and candidate.netloc.lower() == root.netloc.lower()

    def _session(self) -> requests.Session:
        session = getattr(self.session_factory, "session", None)
        if session is None:
            session = requests.Session()
            session.headers.update({"User-Agent": USER_AGENT})
            self.session_factory.session = session
        return session

    def _robot_parser(self, url: str) -> RobotFileParser:
        root = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}"
        with self._robot_lock:
            parser = self.robot_parsers.get(root)
            if parser is not None:
                return parser

            parser = RobotFileParser()
            parser.set_url(urljoin(root, "/robots.txt"))
            try:
                response = self._session().get(parser.url, timeout=self.timeout)
                parser.parse(response.text.splitlines())
            except requests.RequestException:
                parser.parse([])

            delay = parser.crawl_delay(USER_AGENT) or parser.crawl_delay("*") or 0.0
            self.robot_parsers[root] = parser
            self.robot_delays[root] = float(delay)
            return parser

    def _delay_for(self, url: str) -> float:
        root = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}"
        self._robot_parser(url)
        return self.robot_delays.get(root, 0.0) or 0.0

    def _wait_for_target(self, url: str) -> None:
        delay = self._delay_for(url)
        host = urlsplit(url).netloc.lower()
        self.delay_manager.delay_seconds = max(self.delay_manager.delay_seconds, delay)
        self.delay_manager.wait_turn(host)

    def _allowed_by_robots(self, url: str) -> bool:
        parser = self._robot_parser(url)
        return parser.can_fetch(USER_AGENT, url)

    def _request(self, url: str) -> requests.Response:
        self._wait_for_target(url)
        return self._session().get(url, timeout=self.timeout, allow_redirects=True)

    @staticmethod
    def _extract_title(html_text: str) -> str:
        soup = BeautifulSoup(html_text, "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        return title

    def _extract_internal_links(self, base_url: str, html_text: str) -> tuple[str, ...]:
        soup = BeautifulSoup(html_text, "html.parser")
        discovered: set[str] = set()
        for tag in soup.find_all("a", href=True):
            candidate = urljoin(base_url, tag["href"])
            candidate, _ = urldefrag(candidate)
            if not self._same_site(candidate, self.start_url):
                continue
            normalized = self._normalize_url(candidate)
            discovered.add(normalized)
        return tuple(sorted(discovered))

    def crawl(self) -> None:
        frontier = [self.start_url]
        depth = 0

        while frontier and depth <= self.max_depth:
            next_frontier: set[str] = set()
            queued = [url for url in frontier if url not in self.visited]
            if not queued:
                depth += 1
                frontier = []
                continue

            with ThreadPoolExecutor(max_workers=self.workers) as executor:
                future_map = {executor.submit(self.fetch_page, url): url for url in queued}
                for future in as_completed(future_map):
                    result = future.result()
                    self.visited.add(result.url)
                    self.discovered[result.url] = result
                    if depth < self.max_depth and result.status_code == 200:
                        next_frontier.update(link for link in result.links if link not in self.visited)

            frontier = sorted(next_frontier)
            depth += 1

    def fetch_page(self, url: str) -> PageResult:
        if not self._allowed_by_robots(url):
            return PageResult(url=url, status_code=None, error="blocked by robots.txt")

        try:
            response = self._request(url)
            title = ""
            links: tuple[str, ...] = ()
            if "text/html" in response.headers.get("Content-Type", ""):
                title = self._extract_title(response.text)
                links = self._extract_internal_links(response.url, response.text)
            return PageResult(url=response.url, status_code=response.status_code, title=title, links=links)
        except requests.RequestException as exc:
            return PageResult(url=url, status_code=None, error=str(exc))

    @staticmethod
    def _base_directories(urls: Iterable[str]) -> list[str]:
        bases: set[str] = set()
        for url in urls:
            parsed = urlsplit(url)
            path = parsed.path or "/"
            if path.endswith("/"):
                base_path = path
            else:
                base_path = posixpath.dirname(path) + "/"
                if base_path == "//":
                    base_path = "/"
            bases.add(urlunsplit((parsed.scheme, parsed.netloc, base_path, "", "")))
        return sorted(bases)

    def brute_force(self) -> None:
        base_urls = self._base_directories(self.discovered.keys() or [self.start_url])

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_map = {}
            for base_url in base_urls:
                for endpoint in COMMON_ENDPOINTS:
                    url = urljoin(base_url, endpoint)
                    future_map[executor.submit(self.probe_url, base_url, url)] = (base_url, url)

            for future in as_completed(future_map):
                result = future.result()
                self.probe_results.append(result)

    def probe_url(self, base_url: str, url: str) -> ProbeResult:
        if not self._same_site(url, self.start_url):
            return ProbeResult(base_url=base_url, url=url, status_code=None, error="off-site")
        if not self._allowed_by_robots(url):
            return ProbeResult(base_url=base_url, url=url, status_code=None, error="blocked by robots.txt")

        try:
            response = self._request(url)
            return ProbeResult(base_url=base_url, url=response.url, status_code=response.status_code)
        except requests.RequestException as exc:
            return ProbeResult(base_url=base_url, url=url, status_code=None, error=str(exc))

    def status_counts(self) -> dict[int, int]:
        counts: dict[int, int] = {}
        for item in list(self.discovered.values()) + self.probe_results:
            status = item.status_code
            if status is None:
                continue
            counts[status] = counts.get(status, 0) + 1
        return counts

    def positive_hits(self) -> list[ProbeResult]:
        return [item for item in self.probe_results if item.status_code in {200, 403, 404}]


def build_report_html(start_url: str, crawler: Crawler) -> str:
    discovered_rows = []
    for result in sorted(crawler.discovered.values(), key=lambda item: item.url):
        discovered_rows.append(
            f"<tr><td>{html.escape(str(result.status_code or 'ERR'))}</td><td>{html.escape(result.url)}</td><td>{html.escape(result.title)}</td></tr>"
        )

    hit_rows = []
    for result in crawler.positive_hits():
        hit_rows.append(
            f"<tr><td>{html.escape(result.base_url)}</td><td>{html.escape(str(result.status_code or 'ERR'))}</td><td>{html.escape(result.url)}</td></tr>"
        )

    counts = crawler.status_counts()
    count_rows = "".join(
        f"<tr><td>{code}</td><td>{count}</td></tr>" for code, count in sorted(counts.items())
    )

    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Project 6 Crawl Report</title>
  <style>
    :root {{ color-scheme: light; --bg: #0f172a; --panel: #111827; --panel2: #1f2937; --text: #e5e7eb; --muted: #9ca3af; --accent: #38bdf8; --good: #34d399; --warn: #f59e0b; --bad: #f87171; }}
    body {{ margin: 0; font-family: Segoe UI, Arial, sans-serif; background: linear-gradient(160deg, #020617 0%, #0f172a 45%, #111827 100%); color: var(--text); }}
    .wrap {{ max-width: 1200px; margin: 0 auto; padding: 32px 20px 60px; }}
    h1 {{ margin: 0 0 8px; font-size: 2rem; }}
    .sub {{ color: var(--muted); margin-bottom: 24px; }}
    .grid {{ display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); margin-bottom: 20px; }}
    .card {{ background: rgba(17,24,39,0.88); border: 1px solid rgba(148,163,184,0.18); border-radius: 16px; padding: 18px; box-shadow: 0 20px 60px rgba(0,0,0,0.25); }}
    .card h2 {{ margin-top: 0; font-size: 1rem; color: var(--accent); }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.92rem; }}
    th, td {{ text-align: left; padding: 10px 8px; border-bottom: 1px solid rgba(148,163,184,0.15); vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 600; }}
    .pill {{ display: inline-block; padding: 4px 10px; border-radius: 999px; background: rgba(56,189,248,0.14); color: #bae6fd; margin-right: 6px; font-size: 0.82rem; }}
    .hits td:nth-child(2) {{ font-weight: 700; }}
  </style>
</head>
<body>
  <div class=\"wrap\">
    <h1>Project 6 Crawl Report</h1>
    <div class=\"sub\">Start URL: {html.escape(start_url)} <span class=\"pill\">2-level crawl</span> <span class=\"pill\">max 10 workers</span> <span class=\"pill\">robots-aware throttling</span></div>
    <div class=\"grid\">
      <div class=\"card\"><h2>Status Summary</h2><table><tr><th>Status</th><th>Count</th></tr>{count_rows}</table></div>
      <div class=\"card\"><h2>Discovered Pages</h2><table><tr><th>Status</th><th>URL</th><th>Title</th></tr>{''.join(discovered_rows)}</table></div>
    </div>
    <div class=\"card hits\"><h2>Brute-Force Hits (200 / 403 / 404)</h2><table><tr><th>Base</th><th>Status</th><th>URL</th></tr>{''.join(hit_rows)}</table></div>
  </div>
</body>
</html>"""


def print_report(start_url: str, crawler: Crawler) -> None:
    print(f"Start URL: {start_url}")
    print(f"Crawl depth: {crawler.max_depth}")
    print(f"Workers: {crawler.workers}")
    print()

    print("Discovered pages:")
    for result in sorted(crawler.discovered.values(), key=lambda item: item.url):
        status = result.status_code if result.status_code is not None else result.error or "ERR"
        print(f"  [{status}] {result.url}")
        if result.title:
            print(f"       title: {result.title}")
    print()

    print("Brute-force hits (200/403/404):")
    for result in sorted(crawler.positive_hits(), key=lambda item: (item.status_code or 0, item.url)):
        print(f"  [{result.status_code}] {result.url} <- {result.base_url}")
    print()

    counts = crawler.status_counts()
    print("Status summary:")
    for status in sorted(counts):
        print(f"  {status}: {counts[status]}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Crawl a site and brute-force common directories/files.")
    parser.add_argument("start_url", nargs="?", default=None, help=f"Starting URL (positional fallback; default: {DEFAULT_TARGET})")
    parser.add_argument("--url", dest="url", default=None, help=f"Starting URL (preferred; default: {DEFAULT_TARGET})")
    parser.add_argument("--depth", type=int, default=DEFAULT_DEPTH, help="Maximum crawl depth (default: 2)")
    parser.add_argument("--workers", type=int, default=MAX_WORKERS, help="Maximum concurrent workers (default: 10)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Fallback delay between requests in seconds (default: 1.0)")
    parser.add_argument("--report", default="project6_crawler_report.html", help="HTML report output path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    start_url = args.url or args.start_url or DEFAULT_TARGET
    crawler = Crawler(
        start_url=start_url,
        max_depth=args.depth,
        workers=args.workers,
        timeout=args.timeout,
        fallback_delay=args.delay,
    )
    crawler.crawl()
    crawler.brute_force()
    print_report(crawler.start_url, crawler)

    report_path = Path(args.report)
    report_path.write_text(build_report_html(crawler.start_url, crawler), encoding="utf-8")
    print()
    print(f"HTML report written to: {report_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())