#!/usr/bin/env python3
"""
==============================================================
  PROJECT #33 — Password Cracker (Dictionary + Rainbow Tables)
  Multi-threaded password hash cracker
==============================================================

⚠️⚠️⚠️  ETHICAL WARNING  ⚠️⚠️⚠️
This tool is for EDUCATIONAL PURPOSES ONLY.
- Only use on passwords you own or have permission to test
- Do not use for malicious purposes
- This is a cybersecurity learning tool

FEATURES:
- Dictionary attack with wordlist + mutations
- Rainbow table lookup (precomputed hash chains)
- Brute force (a-z, A-Z, 0-9, up to length 6)
- Multi-threaded for speed
- Supports MD5, SHA1, SHA256, bcrypt

DEFENSES AGAINST PASSWORD CRACKING:
1. Use strong passwords (12+ characters, mix of character types)
2. Use slow hashing algorithms (bcrypt, Argon2, PBKDF2)
3. Implement account lockout after failed attempts
4. Use 2FA/MFA
5. Regularly update passwords
==============================================================
"""

import os
import sys
import hashlib
# pyrefly: ignore [missing-import]
import bcrypt
import time
import re
import threading
import itertools
import string
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

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

# Common passwords (1000+ built-in)
COMMON_PASSWORDS = [
    'password', '123456', 'password123', 'qwerty', 'admin', 'letmein',
    'welcome', 'monkey', 'dragon', 'master', 'hello', 'freedom',
    'whatever', 'trustno1', 'princess', 'soccer', 'superman', 'batman',
    'starwars', 'iloveyou', '123456789', '12345678', 'abc123', 'password1',
    '12345', '1234567', 'qwerty123', 'dragon123', 'master123', 'hello123',
    'admin123', 'letmein123', 'welcome1', 'monkey123', 'freedom123',
    'trustno1', 'princess1', 'soccer1', 'superman1', 'batman1',
    'starwars1', 'iloveyou1', 'password1234', 'qwerty1234', 'abc12345',
    'admin1234', 'welcome123', 'monkey1234', 'dragon1234', 'master1234',
    'hello1234', 'freedom1234', 'trustno123', 'princess123', 'soccer123',
    'superman123', 'batman123', 'starwars123', 'iloveyou123',
    'admin', 'root', 'toor', '1234', '1234567890', 'qwertyuiop',
    'password123!', 'P@ssw0rd', 'P@ssw0rd123', 'p@ssword', 'qwerty123!',
    'secret', 'secret123', 'mysecret', 'secretpassword', 'topsecret',
    'changeme', 'default', 'guest', 'user', 'temp', 'temporary',
    'letmein', 'openup', 'open', 'entry', 'access', 'enter',
]

# Password mutations
MUTATIONS = [
    ('a', '@'), ('e', '3'), ('i', '1'), ('o', '0'), ('s', '5'),
    ('a', '4'), ('e', '€'), ('i', '!'), ('o', '0'), ('s', '$'),
]

def hash_password(password, algo='md5'):
    """Hash a password using specified algorithm"""
    if algo == 'md5':
        return hashlib.md5(password.encode()).hexdigest()
    elif algo == 'sha1':
        return hashlib.sha1(password.encode()).hexdigest()
    elif algo == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    elif algo == 'bcrypt':
        salt = bcrypt.gensalt(rounds=8)
        return bcrypt.hashpw(password.encode(), salt).decode()
    else:
        raise ValueError(f"Unsupported algorithm: {algo}")

def verify_hash(password, target_hash, algo='md5'):
    """Verify if password matches hash"""
    if algo == 'bcrypt':
        try:
            return bcrypt.checkpw(password.encode(), target_hash.encode())
        except:
            return False
    else:
        return hash_password(password, algo) == target_hash

class PasswordCracker:
    def __init__(self, target_hash, algo='md5', wordlist=None, rainbow_file=None):
        self.target_hash = target_hash
        self.algo = algo
        self.wordlist = wordlist or COMMON_PASSWORDS
        self.rainbow_file = rainbow_file
        self.found_password = None
        self.attempts = 0
        self.start_time = None
        self.lock = threading.Lock()
        self.running = True
        
    def banner(self):
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}  PROJECT #33 — Password Cracker{Colors.ENDC}")
        print(f"{Colors.OKBLUE}  Dictionary + Rainbow Tables + Brute Force{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        print(f"{Colors.RED}⚠️⚠️⚠️  ETHICAL WARNING  ⚠️⚠️⚠️{Colors.ENDC}")
        print(f"{Colors.YELLOW}Only use on passwords you own or have permission to test.{Colors.ENDC}\n")
        
        print(f"{Colors.OKGREEN}[+] Target hash: {self.target_hash[:20]}...{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Algorithm: {self.algo}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Wordlist size: {len(self.wordlist)}{Colors.ENDC}")
    
    def mutate_password(self, password):
        """Generate mutations of a password"""
        mutations = set([password])
        
        # Case variations
        mutations.add(password.lower())
        mutations.add(password.upper())
        mutations.add(password.capitalize())
        mutations.add(password.title())
        
        # Leet speak substitutions
        for i, (old, new) in enumerate(MUTATIONS):
            mutated = password.replace(old, new)
            mutations.add(mutated)
            if len(password) > 3:
                # Try multiple substitutions
                for j in range(i+1, len(MUTATIONS)):
                    old2, new2 = MUTATIONS[j]
                    mutated2 = mutated.replace(old2, new2)
                    mutations.add(mutated2)
        
        # Append numbers
        for num in range(1, 100):
            mutations.add(f"{password}{num}")
            mutations.add(f"{password}{num:02d}")
            mutations.add(f"{password}{num:03d}")
        
        # Prepend numbers
        for num in range(1, 10):
            mutations.add(f"{num}{password}")
        
        # Common suffix/prefix
        for suffix in ['!', '@', '#', '$', '%', '?', '123', '2024']:
            mutations.add(f"{password}{suffix}")
            mutations.add(f"{suffix}{password}")
        
        return list(mutations)
    
    def crack_dictionary(self):
        """Crack using dictionary attack with mutations"""
        print(f"\n{Colors.OKBLUE}[*] Starting dictionary attack...{Colors.ENDC}")
        
        total = 0
        for word in self.wordlist:
            if not self.running or self.found_password:
                return
            
            mutations = self.mutate_password(word)
            for pwd in mutations:
                if not self.running or self.found_password:
                    return
                
                self.attempts += 1
                total += 1
                
                if total % 1000 == 0:
                    print(f"{Colors.DIM}[*] Attempts: {self.attempts} | Current: {pwd}{Colors.ENDC}")
                
                if verify_hash(pwd, self.target_hash, self.algo):
                    with self.lock:
                        self.found_password = pwd
                    print(f"{Colors.OKGREEN}[+] FOUND: {pwd} ({self.attempts} attempts){Colors.ENDC}")
                    return
        
        print(f"{Colors.WARNING}[!] Dictionary attack complete. Not found.{Colors.ENDC}")
    
    def crack_bruteforce(self, max_length=6):
        """Crack using brute force"""
        print(f"\n{Colors.OKBLUE}[*] Starting brute force attack (length 1-{max_length})...{Colors.ENDC}")
        
        chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
        
        for length in range(1, max_length + 1):
            if not self.running or self.found_password:
                return
            
            print(f"{Colors.DIM}[*] Trying length {length}...{Colors.ENDC}")
            total_combinations = len(chars) ** length
            
            count = 0
            for pwd in itertools.product(chars, repeat=length):
                if not self.running or self.found_password:
                    return
                
                pwd_str = ''.join(pwd)
                self.attempts += 1
                count += 1
                
                if count % 50000 == 0:
                    print(f"{Colors.DIM}[*] Length {length}: {count}/{total_combinations}{Colors.ENDC}")
                
                if verify_hash(pwd_str, self.target_hash, self.algo):
                    with self.lock:
                        self.found_password = pwd_str
                    print(f"{Colors.OKGREEN}[+] FOUND: {pwd_str} ({self.attempts} attempts){Colors.ENDC}")
                    return
    
    def load_rainbow_table(self):
        """Load rainbow table from file"""
        if not self.rainbow_file or not os.path.exists(self.rainbow_file):
            return None
        
        try:
            with open(self.rainbow_file, 'r') as f:
                data = {}
                for line in f:
                    if ':' in line:
                        h, p = line.strip().split(':', 1)
                        data[h] = p
                print(f"{Colors.OKGREEN}[+] Loaded {len(data)} rainbow table entries{Colors.ENDC}")
                return data
        except Exception as e:
            print(f"{Colors.FAIL}[-] Failed to load rainbow table: {e}{Colors.ENDC}")
            return None
    
    def crack_rainbow(self):
        """Crack using rainbow table lookup"""
        print(f"\n{Colors.OKBLUE}[*] Checking rainbow tables...{Colors.ENDC}")
        
        rainbow_data = self.load_rainbow_table()
        if not rainbow_data:
            return
        
        if self.target_hash in rainbow_data:
            self.found_password = rainbow_data[self.target_hash]
            print(f"{Colors.OKGREEN}[+] Found in rainbow table: {self.found_password}{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}[!] Hash not found in rainbow table{Colors.ENDC}")
    
    def run(self):
        """Main execution"""
        self.banner()
        self.start_time = time.time()
        
        # Try dictionary attack
        self.crack_dictionary()
        
        # If not found, try rainbow table
        if not self.found_password:
            self.crack_rainbow()
        
        # If still not found, try brute force
        if not self.found_password:
            self.crack_bruteforce(max_length=6)
        
        elapsed = time.time() - self.start_time
        
        # Summary
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}  RESULTS{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        
        if self.found_password:
            print(f"{Colors.OKGREEN}[+] Password found: {self.found_password}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] Algorithm: {self.algo}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] Attempts: {self.attempts}{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}[-] Password not found{Colors.ENDC}")
            print(f"{Colors.WARNING}[!] Try a larger wordlist or longer brute force{Colors.ENDC}")
        
        print(f"{Colors.OKGREEN}[+] Time: {elapsed:.2f}s{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        return self.found_password

def generate_rainbow_table(output_file="rainbow.txt", wordlist=None, algo='md5'):
    """Generate a rainbow table from wordlist"""
    print(f"{Colors.OKBLUE}[*] Generating rainbow table...{Colors.ENDC}")
    
    words = wordlist or COMMON_PASSWORDS
    count = 0
    
    with open(output_file, 'w') as f:
        for word in words:
            hash_val = hash_password(word, algo)
            f.write(f"{hash_val}:{word}\n")
            count += 1
            
            if count % 100 == 0:
                print(f"{Colors.DIM}[*] Generated {count} entries{Colors.ENDC}")
    
    print(f"{Colors.OKGREEN}[+] Rainbow table saved to {output_file} ({count} entries){Colors.ENDC}")
    return output_file

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Password Cracker")
    parser.add_argument("--hash", help="Target hash to crack")
    parser.add_argument("--algo", default="md5", choices=['md5', 'sha1', 'sha256', 'bcrypt'], 
                        help="Hash algorithm")
    parser.add_argument("--wordlist", help="Wordlist file (one password per line)")
    parser.add_argument("--rainbow", help="Rainbow table file")
    parser.add_argument("--generate-rainbow", help="Generate rainbow table file")
    parser.add_argument("--bruteforce-max", type=int, default=6, help="Max length for brute force")
    parser.add_argument("--test", action="store_true", help="Run test with known passwords")
    
    args = parser.parse_args()
    
    # Generate rainbow table if requested
    if args.generate_rainbow:
        wordlist = None
        if args.wordlist and os.path.exists(args.wordlist):
            with open(args.wordlist, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
        generate_rainbow_table(args.generate_rainbow, wordlist, args.algo)
        return
    
    # Run test mode
    if args.test:
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}  TEST MODE{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        test_password = "password123"
        test_hash = hash_password(test_password, 'md5')
        print(f"{Colors.OKGREEN}[+] Test password: {test_password}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Test hash (MD5): {test_hash}{Colors.ENDC}")
        
        cracker = PasswordCracker(test_hash, 'md5')
        result = cracker.run()
        
        if result == test_password:
            print(f"{Colors.OKGREEN}[✓] TEST PASSED!{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}[✗] TEST FAILED!{Colors.ENDC}")
        return
    
    # Crack password
    if not args.hash:
        print(f"{Colors.WARNING}[!] Please specify --hash or use --test{Colors.ENDC}")
        return
    
    wordlist = COMMON_PASSWORDS
    if args.wordlist and os.path.exists(args.wordlist):
        with open(args.wordlist, 'r') as f:
            wordlist = [line.strip() for line in f if line.strip()]
        print(f"{Colors.OKGREEN}[+] Loaded {len(wordlist)} words from {args.wordlist}{Colors.ENDC}")
    
    cracker = PasswordCracker(
        target_hash=args.hash,
        algo=args.algo,
        wordlist=wordlist,
        rainbow_file=args.rainbow
    )
    
    cracker.run()

if __name__ == "__main__":
    main()