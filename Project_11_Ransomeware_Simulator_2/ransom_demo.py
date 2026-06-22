#!/usr/bin/env python3
"""
============================================================
  PROJECT #11 — Ransomware Simulator  |  DECRYPTOR
  100 Ethical Hacking Projects Series
  Reverses ransom_sim.py encryption using saved key file.
============================================================
USAGE
------
  python3 ransom_decrypt.py --dir ./ransom_lab
  python3 ransom_decrypt.py --dir /tmp/ransom_lab --dry-run
============================================================
"""

import argparse, os, sys, time
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken

R="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
YELLOW="\033[93m";CYAN="\033[96m";MAGENTA="\033[95m";DIM="\033[2m"
def c(t, code): return f"{code}{t}{R}"

# CHANGED: Now uses current working directory instead of home
DEFAULT_LAB_DIR = Path.cwd() / "ransom_lab"
KEY_FILE        = "ransom_sim.key"
ENC_EXT         = ".encrypted"
RANSOM_NOTE     = "README_RESTORE.txt"

def decrypt_file(enc_path: Path, fernet: Fernet, dry_run: bool) -> tuple[bool, str]:
    """
    Read .encrypted file → AES-256 decrypt → restore original.
    original name = enc_path with .encrypted stripped.
    """
    # strip .encrypted to get original name
    orig_name = enc_path.stem   # e.g. "document.txt.encrypted" → "document.txt"
    # Path.stem only strips last suffix — need to handle double ext
    if enc_path.name.endswith(ENC_EXT):
        orig_name = enc_path.name[:-len(ENC_EXT)]
    orig_path = enc_path.parent / orig_name

    try:
        ciphertext = enc_path.read_bytes()
        if dry_run:
            return True, str(orig_path.relative_to(enc_path.parent.parent
                              if enc_path.parent.name != enc_path.parent.parent.name
                              else enc_path.parent))
        plaintext = fernet.decrypt(ciphertext)
        orig_path.write_bytes(plaintext)
        enc_path.unlink()   # remove .encrypted file
        return True, str(orig_name)
    except InvalidToken:
        return False, f"INVALID KEY — cannot decrypt {enc_path.name}"
    except Exception as e:
        return False, str(e)


def run_decryptor(lab_dir: Path, dry_run: bool):
    print()
    print(c("  ╔══════════════════════════════════════════════════════╗", GREEN))
    print(c("  ║   PROJECT #11 · RANSOMWARE SIMULATOR — DECRYPTOR     ║", GREEN))
    print(c("  ║   Restoring files from AES-256 encryption             ║", GREEN))
    print(c("  ╚══════════════════════════════════════════════════════╝", GREEN))
    print()

    if not lab_dir.exists():
        print(c(f"  [ERROR] Directory not found: {lab_dir}", RED)); sys.exit(1)

    # load key
    key_path = lab_dir / KEY_FILE
    if not key_path.exists():
        print(c(f"  [ERROR] Key file not found: {key_path}", RED))
        print(c("  The key is required to decrypt. Without it, files are unrecoverable.", YELLOW))
        print(c("  This demonstrates why ransomware is so destructive — C2 holds the key.", RED))
        sys.exit(1)

    key    = key_path.read_bytes()
    fernet = Fernet(key)

    print(f"  Lab dir  : {c(str(lab_dir), YELLOW)}")
    print(f"  Key file : {c(str(key_path), MAGENTA)}")
    print(f"  Key      : {c(key.decode()[:32]+'…', DIM)}")
    print(f"  Mode     : {c('DRY RUN', MAGENTA) if dry_run else c('LIVE DECRYPTION', GREEN+BOLD)}")

    # find encrypted files
    enc_files = sorted(lab_dir.rglob(f"*{ENC_EXT}"))
    if not enc_files:
        print(c(f"\n  No {ENC_EXT} files found — already decrypted or nothing was encrypted.", YELLOW))
        return

    print(c(f"\n  ── PRE-DECRYPTION STATE ─────────────────────────────────", CYAN))
    print(f"  {'FILE':<55}  {'SIZE':>8}")
    print("  " + "─"*65)
    for p in enc_files:
        rel = p.relative_to(lab_dir)
        print(f"  {c(str(rel), YELLOW):<64}  {str(p.stat().st_size)+' B':>8}")
    print(f"\n  Found {c(str(len(enc_files)), BOLD)} encrypted file(s)")

    if dry_run:
        print(c("\n  DRY RUN — showing what would be restored:", CYAN))
        for p in enc_files:
            orig = p.name[:-len(ENC_EXT)]
            print(f"  {c(p.name, YELLOW)} → {c(orig, GREEN)}")
        print(c("\n  DRY RUN complete — no files modified.", YELLOW))
        return

    # decrypt
    print(c(f"\n  ── DECRYPTING ────────────────────────────────────────────", GREEN))
    ok_count = fail_count = 0
    t0 = time.time()

    for enc_path in enc_files:
        ok, info = decrypt_file(enc_path, fernet, dry_run)
        if ok:
            ok_count += 1
            rel_enc  = enc_path.relative_to(lab_dir)
            orig_name = enc_path.name[:-len(ENC_EXT)]
            print(f"  {c('RESTORED', GREEN):<22}  {c(str(rel_enc), DIM)} → {c(orig_name, GREEN)}")
        else:
            fail_count += 1
            print(f"  {c('FAILED', RED):<22}  {enc_path.name}: {info}")

    elapsed = time.time() - t0

    # remove ransom note + key after successful full decryption
    if fail_count == 0:
        for cleanup in [RANSOM_NOTE, KEY_FILE]:
            p = lab_dir / cleanup
            if p.exists():
                p.unlink()
                print(c(f"  Cleaned up: {cleanup}", DIM))

    # post state
    print(c(f"\n  ── POST-DECRYPTION STATE ────────────────────────────────", CYAN))
    remaining = list(lab_dir.rglob("*"))
    plain_files = [p for p in remaining if p.is_file() and not p.name.endswith(ENC_EXT)]
    print(f"  {'FILE':<55}  {'SIZE':>8}")
    print("  " + "─"*65)
    for p in sorted(plain_files):
        rel = p.relative_to(lab_dir)
        print(f"  {c(str(rel), GREEN):<64}  {str(p.stat().st_size)+' B':>8}")

    print()
    print(c(f"  ── SUMMARY ────────────────────────────────────────────────", CYAN))
    print(f"  Files restored  : {c(str(ok_count), GREEN+BOLD)}")
    print(f"  Failed          : {c(str(fail_count), RED if fail_count else DIM)}")
    print(f"  Time elapsed    : {c(f'{elapsed:.2f}s', DIM)}")
    if fail_count == 0:
        print(c("\n  ✔ ALL FILES FULLY RESTORED — directory is clean.", GREEN+BOLD))
    else:
        print(c(f"\n  ⚠ {fail_count} file(s) could not be decrypted — key mismatch or corruption.", YELLOW))
    print()


def main():
    parser = argparse.ArgumentParser(description="Project #11 — Ransomware Decryptor")
    parser.add_argument("--dir",     default=str(DEFAULT_LAB_DIR),
                        help=f"Lab directory (default: ./ransom_lab)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview what would be restored (no changes)")
    args = parser.parse_args()
    run_decryptor(Path(args.dir).expanduser().resolve(), args.dry_run)

if __name__ == "__main__":
    main()



# #!/usr/bin/env python3
# """
# Complete Ransomware Simulator Demo
# Shows: Original files -> Encrypted files -> Backup files
# All in the same directory!
# """

# import os
# import sys
# import shutil
# from pathlib import Path
# from cryptography.fernet import Fernet

# # Colors for output
# GREEN = '\033[92m'
# RED = '\033[91m'
# YELLOW = '\033[93m'
# BLUE = '\033[94m'
# MAGENTA = '\033[95m'
# CYAN = '\033[96m'
# RESET = '\033[0m'
# BOLD = '\033[1m'

# def print_color(text, color):
#     print(f"{color}{text}{RESET}")

# def setup_demo():
#     """Create dummy files in current directory"""
#     demo_dir = Path.cwd() / "ransom_demo"
    
#     # Clean old demo
#     if demo_dir.exists():
#         shutil.rmtree(demo_dir)
    
#     demo_dir.mkdir(exist_ok=True)
    
#     # Create dummy files
#     dummy_files = {
#         "personal_info.txt": """Name: John Doe
# Email: john@example.com
# Phone: 555-1234
# Address: 123 Main St
# SSN: 123-45-6789""",
        
#         "bank_details.txt": """Account: 987654321
# Routing: 123456789
# Balance: $5,000
# PIN: 1234""",
        
#         "passwords.txt": """Facebook: john@example.com / pass123
# Gmail: john.doe@gmail.com / mypassword
# Work Email: jdoe@company.com / WorkPass2024
# AWS Key: AKIAIOSFODNN7EXAMPLE""",
        
#         "secret_notes.txt": """Meeting with CEO tomorrow at 2PM
# Quarterly profits: $2.5M
# New product launch date: Dec 15
# Client negotiation strategy: Give 20% discount""",
        
#         "backup_config.json": """{
#     "database": "production_db",
#     "username": "admin",
#     "password": "AdminPass123",
#     "server": "192.168.1.100",
#     "backup_schedule": "daily"
# }"""
#     }
    
#     print_color("\n" + "="*70, CYAN)
#     print_color("  STEP 1: CREATING DUMMY FILES", BOLD + CYAN)
#     print_color("="*70, CYAN)
    
#     for filename, content in dummy_files.items():
#         filepath = demo_dir / filename
#         filepath.write_text(content)
#         print_color(f"  ✓ Created: {filename} ({len(content)} bytes)", GREEN)
    
#     # Create subdirectory with more files
#     subdir = demo_dir / "confidential"
#     subdir.mkdir(exist_ok=True)
    
#     subdir_files = {
#         "client_list.txt": "Client A: $50,000\nClient B: $75,000\nClient C: $100,000",
#         "api_keys.txt": "API_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc\nSECRET=test_secret_123"
#     }
    
#     for filename, content in subdir_files.items():
#         filepath = subdir / filename
#         filepath.write_text(content)
#         print_color(f"  ✓ Created: confidential/{filename} ({len(content)} bytes)", GREEN)
    
#     print_color(f"\n  Demo directory: {demo_dir}", YELLOW)
#     return demo_dir

# def encrypt_files(demo_dir):
#     """Encrypt files and save as .encrypted (preserve originals)"""
#     print_color("\n" + "="*70, CYAN)
#     print_color("  STEP 2: ENCRYPTING FILES (Preserving Originals)", BOLD + CYAN)
#     print_color("="*70, CYAN)
    
#     # Generate encryption key
#     key = Fernet.generate_key()
#     fernet = Fernet(key)
    
#     # Save key
#     key_file = demo_dir / "encryption_key.key"
#     key_file.write_bytes(key)
#     print_color(f"  ✓ Encryption key saved: {key_file}", GREEN)
    
#     # Create encrypted files folder
#     enc_folder = demo_dir / "encrypted_copies"
#     enc_folder.mkdir(exist_ok=True)
    
#     encrypted_count = 0
    
#     # Walk through all files
#     for filepath in demo_dir.rglob("*"):
#         if not filepath.is_file():
#             continue
#         # Skip key file, readme, and already encrypted files
#         if filepath.name in ["encryption_key.key", "README_RESTORE.txt", "vaccine.txt"]:
#             continue
#         if filepath.suffix == ".encrypted":
#             continue
        
#         try:
#             # Read original file
#             with open(filepath, "rb") as f:
#                 original_data = f.read()
            
#             # Encrypt
#             encrypted_data = fernet.encrypt(original_data)
            
#             # Save encrypted copy
#             rel_path = filepath.relative_to(demo_dir)
#             enc_path = enc_folder / f"{filepath.name}.encrypted"
#             enc_path.write_bytes(encrypted_data)
            
#             print_color(f"  🔒 Encrypted: {rel_path} -> encrypted_copies/{filepath.name}.encrypted", YELLOW)
#             encrypted_count += 1
            
#         except Exception as e:
#             print_color(f"  ✗ Failed: {filepath.name} - {e}", RED)
    
#     # Create ransom note
#     note_content = f"""
# {'='*70}
#   SECURITY SIMULATION - EDUCATIONAL PURPOSE ONLY
# {'='*70}

# Your files have been encrypted as a simulation!

# Original files are PRESERVED in: {demo_dir}
# Encrypted copies are in: {demo_dir}/encrypted_copies/

# Encryption key is saved in: {demo_dir}/encryption_key.key

# TO DECRYPT:
# Run: python3 ransom_demo.py --decrypt

# This is a safe educational simulation - no actual ransomware!
# {'='*70}
# """
#     note_file = demo_dir / "README_RESTORE.txt"
#     note_file.write_text(note_content)
#     print_color(f"  ✓ Ransom note created: README_RESTORE.txt", GREEN)
    
#     print_color(f"\n  Total encrypted: {encrypted_count} files", BOLD + GREEN)
#     print_color(f"  Original files preserved in: {demo_dir}", BOLD + GREEN)
#     print_color(f"  Encrypted copies in: {enc_folder}", BOLD + YELLOW)
    
#     return key

# def decrypt_files(demo_dir, create_backup=True):
#     """Decrypt files from encrypted_copies folder"""
#     print_color("\n" + "="*70, CYAN)
#     print_color("  STEP 3: DECRYPTING FILES (With Backup Option)", BOLD + CYAN)
#     print_color("="*70, CYAN)
    
#     # Load encryption key
#     key_file = demo_dir / "encryption_key.key"
#     if not key_file.exists():
#         print_color(f"  ✗ Error: Key file not found! Cannot decrypt.", RED)
#         return 0
    
#     key = key_file.read_bytes()
#     fernet = Fernet(key)
    
#     enc_folder = demo_dir / "encrypted_copies"
#     if not enc_folder.exists():
#         print_color(f"  ✗ Error: No encrypted files folder found!", RED)
#         return 0
    
#     # Find all encrypted files
#     enc_files = list(enc_folder.glob("*.encrypted"))
    
#     if not enc_files:
#         print_color(f"  No encrypted files found to decrypt.", YELLOW)
#         return 0
    
#     decrypted_count = 0
    
#     for enc_path in enc_files:
#         # Original filename (remove .encrypted)
#         orig_name = enc_path.stem  # Gets filename without .encrypted
#         orig_path = demo_dir / orig_name
        
#         try:
#             # Read encrypted data
#             with open(enc_path, "rb") as f:
#                 encrypted_data = f.read()
            
#             # Decrypt
#             decrypted_data = fernet.decrypt(encrypted_data)
            
#             # Create backup if original exists
#             if orig_path.exists() and create_backup:
#                 backup_path = demo_dir / f"{orig_name}.backup"
#                 shutil.copy2(orig_path, backup_path)
#                 print_color(f"  💾 Backup created: {backup_path.name}", MAGENTA)
            
#             # Write decrypted file (overwrite or create)
#             orig_path.write_bytes(decrypted_data)
#             print_color(f"  ✓ Decrypted: {orig_name}", GREEN)
#             decrypted_count += 1
            
#         except Exception as e:
#             print_color(f"  ✗ Failed: {enc_path.name} - {e}", RED)
    
#     print_color(f"\n  Total decrypted: {decrypted_count} files", BOLD + GREEN)
#     if create_backup:
#         print_color(f"  Backups created for existing files (*.backup)", YELLOW)
    
#     return decrypted_count

# def show_file_structure(demo_dir):
#     """Display all files in the demo directory"""
#     print_color("\n" + "="*70, CYAN)
#     print_color("  FILE STRUCTURE OVERVIEW", BOLD + CYAN)
#     print_color("="*70, CYAN)
    
#     for item in sorted(demo_dir.rglob("*")):
#         if item.is_file():
#             size = item.stat().st_size
#             rel_path = item.relative_to(demo_dir)
            
#             # Color code different file types
#             if item.suffix == ".encrypted":
#                 print_color(f"  🔒 {rel_path} ({size} bytes) - ENCRYPTED COPY", YELLOW)
#             elif item.suffix == ".backup":
#                 print_color(f"  💾 {rel_path} ({size} bytes) - BACKUP", MAGENTA)
#             elif item.name == "encryption_key.key":
#                 print_color(f"  🔑 {rel_path} ({size} bytes) - ENCRYPTION KEY", RED)
#             elif item.name == "README_RESTORE.txt":
#                 print_color(f"  📄 {rel_path} ({size} bytes) - RANSOM NOTE", BLUE)
#             else:
#                 print_color(f"  📁 {rel_path} ({size} bytes) - ORIGINAL", GREEN)

# def main():
#     import argparse
    
#     parser = argparse.ArgumentParser(description="Ransomware Simulation Demo")
#     parser.add_argument("--decrypt", action="store_true", help="Decrypt files")
#     parser.add_argument("--no-backup", action="store_true", help="Don't create backups during decryption")
#     args = parser.parse_args()
    
#     demo_dir = Path.cwd() / "ransom_demo"
    
#     if args.decrypt:
#         if not demo_dir.exists():
#             print_color(f"\n  Error: Demo directory not found! Run without --decrypt first.", RED)
#             sys.exit(1)
#         decrypt_files(demo_dir, not args.no_backup)
#         show_file_structure(demo_dir)
#     else:
#         # Run full demo
#         demo_dir = setup_demo()
#         show_file_structure(demo_dir)
        
#         # Ask user if they want to encrypt
#         print_color("\n" + "="*70, CYAN)
#         response = input(f"\n  Do you want to encrypt the files? (y/N): ")
        
#         if response.lower() == 'y':
#             encrypt_files(demo_dir)
#             show_file_structure(demo_dir)
            
#             # Ask if they want to decrypt
#             response2 = input(f"\n  Do you want to decrypt the files? (y/N): ")
#             if response2.lower() == 'y':
#                 decrypt_files(demo_dir, True)
#                 show_file_structure(demo_dir)
        
#         print_color("\n" + "="*70, GREEN)
#         print_color("  DEMO COMPLETE!", BOLD + GREEN)
#         print_color("="*70, GREEN)
#         print(f"\n  Demo directory: {demo_dir}")
#         print(f"\n  To run again:")
#         print(f"    python3 ransom_demo.py          # Run full demo")
#         print(f"    python3 ransom_demo.py --decrypt # Only decrypt")

# if __name__ == "__main__":
#     main()