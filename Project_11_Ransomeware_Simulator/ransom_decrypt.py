#!/usr/bin/env python3
import os
import sys
from cryptography.fernet import Fernet

LAB_DIR = os.path.join(os.getcwd(), "ransom_lab")
KEY_FILE = os.path.join(LAB_DIR, "system_key.key")
NOTE_FILE = os.path.join(LAB_DIR, "ALERT_README.txt")

def execute_recovery():
    print("=== INITIALIZING RECOVERY & DECRYPTION UTILITY ===")
    
    if not os.path.exists(KEY_FILE):
        print(f"[!] Critical Error: Secret key token missing at {KEY_FILE}")
        sys.exit(1)

    with open(KEY_FILE, "rb") as k_file:
        key = k_file.read()

    fernet = Fernet(key)
    restored_count = 0

    for root, _, files in os.walk(LAB_DIR):
        for file in files:
            if not file.endswith(".locked"):
                continue
                
            file_path = os.path.join(root, file)
            original_path = file_path.rsplit(".locked", 1)[0]

            try:
                with open(file_path, "rb") as f:
                    encrypted_payload = f.read()

                decrypted_bytes = fernet.decrypt(encrypted_payload)

                with open(original_path, "wb") as f:
                    f.write(decrypted_bytes)

                os.remove(file_path)
                print(f"   [+] Restored: {os.path.basename(original_path)}")
                restored_count += 1
            except Exception as e:
                print(f"   [-] Decryption failed for {file}: {e}")

    # Clean up tracking artifacts
    if os.path.exists(NOTE_FILE):
        os.remove(NOTE_FILE)
    if os.path.exists(KEY_FILE):
        os.remove(KEY_FILE)

    print(f"\n[+] Recovery processing concluded. Total items restored: {restored_count}")

if __name__ == "__main__":
    execute_recovery()
