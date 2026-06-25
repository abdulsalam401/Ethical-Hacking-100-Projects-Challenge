#!/usr/bin/env python3
"""
Project #33: Cryptographic Audit Platform - Multi-Threaded Hash Matcher
Architecture: ThreadPoolExecutor + Rule-Based Dictionary Mutation + Precomputed Map Lookup.
"""

import sys
import hashlib
import itertools
import argparse
from concurrent.futures import ThreadPoolExecutor

try:
    # pyrefly: ignore [missing-import]
    import bcrypt
except ImportError:
    print("[-] Dependency Missing: Run 'pip3 install bcrypt'")
    sys.exit(1)

# Terminal UI Palettes
G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"; R = "\033[91m"; BOLD = "\033[1m"; RESET = "\033[0m"

BANNER = f"""
======================================================================
  🔐 CRYPTO-AUDIT: PERFORMANCE BENCHMARKING & PASSPHRASE MATCHER
======================================================================
"""

# Embedded Precomputed Reference Lookup Data Map (Simulated Static Rainbow Table)
RAINBOW_TABLE = {
    "5f4dcc3b5aa765d61d8327deb882cf99": "password",
    "e10adc3949ba59abbe56e057f20f883e": "123456",
    "482c811da5d5b4bc6d497ffa98491e38": "password123",
    "d8578edf8458ce06fbc5bb76a58c5ca4": "qwerty",
    "21232f297a57a5a743894a0e4a801fc3": "admin",
    "0d107d09f5bbe40cade3de5c71e9e9b7": "letmein",
    "40be4e59b9a2a2b5dffb918c0e86b3d7": "welcome",
    "b7e283a09511d95d6eac86e39e7942c0": "password123!",
    "161ebd7d45089b3446ee4e0d86dbcf92": "P@ssw0rd",
    "ccf5538dc31d435d6bab145c924041d8": "P@ssw0rd123"
}

BUILTIN_WORDLIST = ["password", "admin", "secret", "welcome", "qwerty", "letmein", "guest"]

def generate_mutations(word):
    """Generates structural alterations to identify policy mutation patterns."""
    mutations = set([word])
    mutations.add(word.upper())
    mutations.add(word.capitalize())
    
    # Simple substitution rules (Leet Speak)
    leet = word.replace('a', '@').replace('s', '$').replace('o', '0').replace('i', '1').replace('e', '3')
    mutations.add(leet)
    mutations.add(leet.capitalize())
    
    # Common appending suffix modifications
    for suffix in ['123', '!', '123!', '1']:
        mutations.add(f"{word}{suffix}")
        mutations.add(f"{word.capitalize()}{suffix}")
        
    return list(mutations)

def verify_hash_match(plain_text, target_hash, hash_type):
    """Checks input text against target signature based on selected hash architecture."""
    if hash_type == 'md5':
        return hashlib.md5(plain_text.encode()).hexdigest() == target_hash
    elif hash_type == 'sha1':
        return hashlib.sha1(plain_text.encode()).hexdigest() == target_hash
    elif hash_type == 'sha256':
        return hashlib.sha256(plain_text.encode()).hexdigest() == target_hash
    elif hash_type == 'bcrypt':
        try:
            # Bcrypt checks incorporate internal crypt-safe salts natively
            return bcrypt.checkpw(plain_text.encode(), target_hash.encode())
        except Exception:
            return False
    return False

def run_brute_force_worker(args):
    """Worker loop executing standalone character permutation evaluation steps."""
    chunk, target_hash, hash_type = args
    for perm in chunk:
        candidate = "".join(perm)
        if verify_hash_match(candidate, target_hash, hash_type):
            return candidate
    return None

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Cryptographic Structural Passphrase Strength Auditor")
    parser.add_argument("--hash", required=True, help="Target cryptographic signature value to process")
    parser.add_argument("--type", required=True, choices=['md5', 'sha1', 'sha256', 'bcrypt'], help="Target digest configuration rule")
    args = parser.parse_args()

    normalized_hash = args.hash.lower().strip()
    
    # Phase 1: Precomputed Direct Mapping Table Query
    print(f"[*] Phase 1: Querying static reference precomputed data records...")
    if normalized_hash in RAINBOW_TABLE:
        print(f"   {G}[+] Structural Match Located via Precomputed Map Repository!{RESET}")
        print(f"       👉 Plain Text Value: {G}{BOLD}{RAINBOW_TABLE[normalized_hash]}{RESET}\n")
        return

    print(f"   [-] No matches found in precomputed tables. Proceeding to active mutation matrices...")

    # Phase 2: Dictionary Mutation Pipeline
    print(f"[*] Phase 2: Processing rule-based input array dictionary arrays...")
    for entry in BUILTIN_WORDLIST:
        candidates = generate_mutations(entry)
        for candidate in candidates:
            if verify_hash_match(candidate, normalized_hash, args.type):
                print(f"   {G}[+] Verification Succeeded via Structural Dictionary Mutation Layer!{RESET}")
                print(f"       👉 Plain Text Value: {G}{BOLD}{candidate}{RESET}\n")
                return

    print(f"   [-] Mutation streams exhausted. Initializing multi-threaded brute-force character pipeline...")

    # Phase 3: Distributed Multi-Threaded Exhaustive Search Space Check
    # Limits maximum length space processing limits to preserve local memory layout state bounds
    print(f"[*] Phase 3: Spawning parallel worker pools tracking character sets [a-z0-9]...")
    chars = string.ascii_lowercase + string.digits
    found_plaintext = None

    # Iterates progressively up to character length bounds limits
    for length in range(1, 5):
        print(f"   [*] Scanning exhaustive space complexity allocations for token strings of length: {length}")
        all_perms = list(itertools.product(chars, repeat=length))
        
        # Segment large configuration loads into chunk blocks for concurrent threads
        chunk_size = max(1, len(all_perms) // 4)
        chunks = [all_perms[i:i + chunk_size] for i in range(0, len(all_perms), chunk_size)]
        worker_tasks = [(chunk, normalized_hash, args.type) for chunk in chunks]

        with ThreadPoolExecutor(max_workers=4) as executor:
            results = executor.map(run_brute_force_worker, worker_tasks)
            for res in results:
                if res:
                    found_plaintext = res
                    break
        
        if found_plaintext:
            print(f"\n   {G}[+] Verification Succeeded via Exhaustive Character Permutation Checks!{RESET}")
            print(f"       👉 Plain Text Value: {G}{BOLD}{found_plaintext}{RESET}\n")
            return

    print(f"\n{R}[─] Audit Complete: Cryptographic validation space checked. No parameter match identified.{RESET}\n")

if __name__ == "__main__":
    import string
    main()
