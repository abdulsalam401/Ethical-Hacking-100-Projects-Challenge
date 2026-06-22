#!/usr/bin/env python3
"""
============================================================
  PROJECT #11 — Ransomware Simulator  |  DECRYPTOR
  100 Ethical Hacking Projects Series
  Reverses ransom_sim.py encryption using saved key file.
  NEW: Decrypts from 'encrypted_files' folder
============================================================
USAGE
------
  python3 ransom_decrypt.py --dir ~/ransom_lab
  python3 ransom_decrypt.py --dir /tmp/ransom_lab --dry-run
============================================================
"""

import argparse, os, sys, time, shutil
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken

R="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
YELLOW="\033[93m";CYAN="\033[96m";MAGENTA="\033[95m";DIM="\033[2m"
def c(t, code): return f"{code}{t}{R}"

DEFAULT_LAB_DIR = Path.home() / "ransom_lab"
KEY_FILE        = "ransom_sim.key"
ENC_EXT         = ".encrypted"
RANSOM_NOTE     = "README_RESTORE.txt"
ENCRYPTED_FOLDER = "encrypted_files"  # NEW: folder containing encrypted files

def decrypt_file_from_folder(enc_path: Path, fernet: Fernet, dest_dir: Path, dry_run: bool) -> tuple[bool, str]:
    """
    Read .encrypted file from encrypted_files folder → AES-256 decrypt → 
    restore original to main directory.
    """
    # Get original name by removing .encrypted extension
    if enc_path.name.endswith(ENC_EXT):
        orig_name = enc_path.name[:-len(ENC_EXT)]
    else:
        orig_name = enc_path.stem
    
    orig_path = dest_dir / orig_name
    
    try:
        ciphertext = enc_path.read_bytes()
        if dry_run:
            return True, str(orig_name)
        
        plaintext = fernet.decrypt(ciphertext)
        
        # If original exists, create backup
        if orig_path.exists() and not dry_run:
            backup_path = dest_dir / f"{orig_name}.backup"
            print(c(f"    Original exists, backed up to: {backup_path.name}", YELLOW))
            shutil.copy2(orig_path, backup_path)
        
        orig_path.write_bytes(plaintext)
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

    # Check for encrypted folder
    enc_folder = lab_dir / ENCRYPTED_FOLDER
    if not enc_folder.exists():
        print(c(f"  [ERROR] Encrypted folder not found: {enc_folder}", RED))
        print(c(f"  No encrypted files found to decrypt.", YELLOW))
        return

    # load key
    key_path = lab_dir / KEY_FILE
    if not key_path.exists():
        print(c(f"  [ERROR] Key file not found: {key_path}", RED))
        print(c("  The key is required to decrypt. Without it, files are unrecoverable.", YELLOW))
        print(c("  This demonstrates why ransomware is so destructive — C2 holds the key.", RED))
        sys.exit(1)

    key    = key_path.read_bytes()
    fernet = Fernet(key)

    print(f"  Lab dir         : {c(str(lab_dir), YELLOW)}")
    print(f"  Encrypted folder: {c(str(enc_folder), MAGENTA)}")
    print(f"  Key file        : {c(str(key_path), MAGENTA)}")
    print(f"  Key             : {c(key.decode()[:32]+'…', DIM)}")
    print(f"  Mode            : {c('DRY RUN', MAGENTA) if dry_run else c('LIVE DECRYPTION', GREEN+BOLD)}")

    # find encrypted files in the encrypted folder
    enc_files = sorted(enc_folder.rglob(f"*{ENC_EXT}"))
    if not enc_files:
        print(c(f"\n  No {ENC_EXT} files found in {ENCRYPTED_FOLDER}/ — nothing to decrypt.", YELLOW))
        return

    print(c(f"\n  ── PRE-DECRYPTION STATE ─────────────────────────────────", CYAN))
    print(f"  {'ENCRYPTED FILE':<55}  {'SIZE':>8}")
    print("  " + "─"*65)
    for p in enc_files:
        rel = p.relative_to(enc_folder)
        print(f"  {c(str(rel), YELLOW):<64}  {str(p.stat().st_size)+' B':>8}")
    print(f"\n  Found {c(str(len(enc_files)), BOLD)} encrypted file(s) in {ENCRYPTED_FOLDER}/")

    if dry_run:
        print(c("\n  DRY RUN — showing what would be restored:", CYAN))
        for p in enc_files:
            orig = p.name[:-len(ENC_EXT)] if p.name.endswith(ENC_EXT) else p.stem
            print(f"  {c(p.name, YELLOW)} → {c(orig, GREEN)} (to {lab_dir})")
        print(c("\n  DRY RUN complete — no files modified.", YELLOW))
        return

    # decrypt
    print(c(f"\n  ── DECRYPTING (from {ENCRYPTED_FOLDER}/ to main directory) ────────────────────────────", GREEN))
    ok_count = fail_count = 0
    t0 = time.time()

    for enc_path in enc_files:
        ok, info = decrypt_file_from_folder(enc_path, fernet, lab_dir, dry_run)
        if ok:
            ok_count += 1
            rel_enc = enc_path.relative_to(enc_folder)
            orig_name = enc_path.name[:-len(ENC_EXT)] if enc_path.name.endswith(ENC_EXT) else enc_path.stem
            print(f"  {c('RESTORED', GREEN):<22}  {c(str(rel_enc), DIM)} → {c(orig_name, GREEN)}")
        else:
            fail_count += 1
            print(f"  {c('FAILED', RED):<22}  {enc_path.name}: {info}")

    elapsed = time.time() - t0

    # Optionally clean up encrypted folder after successful decryption
    if fail_count == 0 and ok_count > 0 and not dry_run:
        print(c(f"\n  ── CLEANUP ────────────────────────────────────────────────", CYAN))
        response = input(f"  Delete all encrypted files from {ENCRYPTED_FOLDER}/? (y/N): ")
        if response.lower() == 'y':
            shutil.rmtree(enc_folder)
            print(c(f"  ✓ Removed {ENCRYPTED_FOLDER}/ folder", GREEN))
            # Also remove ransom note and key
            for cleanup in [RANSOM_NOTE, KEY_FILE]:
                p = lab_dir / cleanup
                if p.exists():
                    p.unlink()
                    print(c(f"  ✓ Cleaned up: {cleanup}", DIM))
        else:
            print(c(f"  Encrypted files preserved in {ENCRYPTED_FOLDER}/", YELLOW))

    # post state - show restored files
    print(c(f"\n  ── POST-DECRYPTION STATE ────────────────────────────────", CYAN))
    remaining_files = [p for p in lab_dir.rglob("*") if p.is_file() and p.suffix != ENC_EXT and p.name not in [KEY_FILE, RANSOM_NOTE]]
    
    if remaining_files:
        print(f"  {'RESTORED FILES':<55}  {'SIZE':>8}")
        print("  " + "─"*65)
        for p in sorted(remaining_files)[:20]:  # Show first 20 files
            if ENCRYPTED_FOLDER not in str(p):
                rel = p.relative_to(lab_dir)
                print(f"  {c(str(rel), GREEN):<64}  {str(p.stat().st_size)+' B':>8}")
        if len(remaining_files) > 20:
            print(f"  ... and {len(remaining_files) - 20} more files")

    print()
    print(c(f"  ── SUMMARY ────────────────────────────────────────────────", CYAN))
    print(f"  Files restored  : {c(str(ok_count), GREEN+BOLD)}")
    print(f"  Failed          : {c(str(fail_count), RED if fail_count else DIM)}")
    print(f"  Time elapsed    : {c(f'{elapsed:.2f}s', DIM)}")
    print(f"  Restored to     : {c(str(lab_dir), GREEN)}")
    
    if fail_count == 0 and ok_count > 0:
        print(c("\n  ✔ ALL FILES FULLY RESTORED!", GREEN+BOLD))
        print(c(f"  Original files are back in {lab_dir}", GREEN))
        print(c(f"  Encrypted copies remain in {ENCRYPTED_FOLDER}/ (can be deleted manually)", YELLOW))
    elif fail_count > 0:
        print(c(f"\n  ⚠ {fail_count} file(s) could not be decrypted — key mismatch or corruption.", YELLOW))
    print()

def main():
    parser = argparse.ArgumentParser(description="Project #11 — Ransomware Decryptor")
    parser.add_argument("--dir",     default=str(DEFAULT_LAB_DIR),
                        help=f"Lab directory (default: {DEFAULT_LAB_DIR})")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview what would be restored (no changes)")
    args = parser.parse_args()
    run_decryptor(Path(args.dir).expanduser().resolve(), args.dry_run)

if __name__ == "__main__":
    main()



    

# #!/usr/bin/env python3
# """
# ============================================================
#   PROJECT #11 — Ransomware Simulator  |  DECRYPTOR
#   100 Ethical Hacking Projects Series
#   Reverses ransom_sim.py encryption using saved key file.
# ============================================================
# USAGE
# ------
#   python3 ransom_decrypt.py --dir ~/ransom_lab
#   python3 ransom_decrypt.py --dir /tmp/ransom_lab --dry-run
# ============================================================
# """

# import argparse, os, sys, time
# from pathlib import Path
# from cryptography.fernet import Fernet, InvalidToken

# R="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
# YELLOW="\033[93m";CYAN="\033[96m";MAGENTA="\033[95m";DIM="\033[2m"
# def c(t, code): return f"{code}{t}{R}"

# DEFAULT_LAB_DIR = Path.home() / "ransom_lab"
# KEY_FILE        = "ransom_sim.key"
# ENC_EXT         = ".encrypted"
# RANSOM_NOTE     = "README_RESTORE.txt"

# def decrypt_file(enc_path: Path, fernet: Fernet, dry_run: bool) -> tuple[bool, str]:
#     """
#     Read .encrypted file → AES-256 decrypt → restore original.
#     original name = enc_path with .encrypted stripped.
#     """
#     # strip .encrypted to get original name
#     orig_name = enc_path.stem   # e.g. "document.txt.encrypted" → "document.txt"
#     # Path.stem only strips last suffix — need to handle double ext
#     if enc_path.name.endswith(ENC_EXT):
#         orig_name = enc_path.name[:-len(ENC_EXT)]
#     orig_path = enc_path.parent / orig_name

#     try:
#         ciphertext = enc_path.read_bytes()
#         if dry_run:
#             return True, str(orig_path.relative_to(enc_path.parent.parent
#                               if enc_path.parent.name != enc_path.parent.parent.name
#                               else enc_path.parent))
#         plaintext = fernet.decrypt(ciphertext)
#         orig_path.write_bytes(plaintext)
#         enc_path.unlink()   # remove .encrypted file
#         return True, str(orig_name)
#     except InvalidToken:
#         return False, f"INVALID KEY — cannot decrypt {enc_path.name}"
#     except Exception as e:
#         return False, str(e)


# def run_decryptor(lab_dir: Path, dry_run: bool):
#     print()
#     print(c("  ╔══════════════════════════════════════════════════════╗", GREEN))
#     print(c("  ║   PROJECT #11 · RANSOMWARE SIMULATOR — DECRYPTOR     ║", GREEN))
#     print(c("  ║   Restoring files from AES-256 encryption             ║", GREEN))
#     print(c("  ╚══════════════════════════════════════════════════════╝", GREEN))
#     print()

#     if not lab_dir.exists():
#         print(c(f"  [ERROR] Directory not found: {lab_dir}", RED)); sys.exit(1)

#     # load key
#     key_path = lab_dir / KEY_FILE
#     if not key_path.exists():
#         print(c(f"  [ERROR] Key file not found: {key_path}", RED))
#         print(c("  The key is required to decrypt. Without it, files are unrecoverable.", YELLOW))
#         print(c("  This demonstrates why ransomware is so destructive — C2 holds the key.", RED))
#         sys.exit(1)

#     key    = key_path.read_bytes()
#     fernet = Fernet(key)

#     print(f"  Lab dir  : {c(str(lab_dir), YELLOW)}")
#     print(f"  Key file : {c(str(key_path), MAGENTA)}")
#     print(f"  Key      : {c(key.decode()[:32]+'…', DIM)}")
#     print(f"  Mode     : {c('DRY RUN', MAGENTA) if dry_run else c('LIVE DECRYPTION', GREEN+BOLD)}")

#     # find encrypted files
#     enc_files = sorted(lab_dir.rglob(f"*{ENC_EXT}"))
#     if not enc_files:
#         print(c(f"\n  No {ENC_EXT} files found — already decrypted or nothing was encrypted.", YELLOW))
#         return

#     print(c(f"\n  ── PRE-DECRYPTION STATE ─────────────────────────────────", CYAN))
#     print(f"  {'FILE':<55}  {'SIZE':>8}")
#     print("  " + "─"*65)
#     for p in enc_files:
#         rel = p.relative_to(lab_dir)
#         print(f"  {c(str(rel), YELLOW):<64}  {str(p.stat().st_size)+' B':>8}")
#     print(f"\n  Found {c(str(len(enc_files)), BOLD)} encrypted file(s)")

#     if dry_run:
#         print(c("\n  DRY RUN — showing what would be restored:", CYAN))
#         for p in enc_files:
#             orig = p.name[:-len(ENC_EXT)]
#             print(f"  {c(p.name, YELLOW)} → {c(orig, GREEN)}")
#         print(c("\n  DRY RUN complete — no files modified.", YELLOW))
#         return

#     # decrypt
#     print(c(f"\n  ── DECRYPTING ────────────────────────────────────────────", GREEN))
#     ok_count = fail_count = 0
#     t0 = time.time()

#     for enc_path in enc_files:
#         ok, info = decrypt_file(enc_path, fernet, dry_run)
#         if ok:
#             ok_count += 1
#             rel_enc  = enc_path.relative_to(lab_dir)
#             orig_name = enc_path.name[:-len(ENC_EXT)]
#             print(f"  {c('RESTORED', GREEN):<22}  {c(str(rel_enc), DIM)} → {c(orig_name, GREEN)}")
#         else:
#             fail_count += 1
#             print(f"  {c('FAILED', RED):<22}  {enc_path.name}: {info}")

#     elapsed = time.time() - t0

#     # remove ransom note + key after successful full decryption
#     if fail_count == 0:
#         for cleanup in [RANSOM_NOTE, KEY_FILE]:
#             p = lab_dir / cleanup
#             if p.exists():
#                 p.unlink()
#                 print(c(f"  Cleaned up: {cleanup}", DIM))

#     # post state
#     print(c(f"\n  ── POST-DECRYPTION STATE ────────────────────────────────", CYAN))
#     remaining = list(lab_dir.rglob("*"))
#     plain_files = [p for p in remaining if p.is_file() and not p.name.endswith(ENC_EXT)]
#     print(f"  {'FILE':<55}  {'SIZE':>8}")
#     print("  " + "─"*65)
#     for p in sorted(plain_files):
#         rel = p.relative_to(lab_dir)
#         print(f"  {c(str(rel), GREEN):<64}  {str(p.stat().st_size)+' B':>8}")

#     print()
#     print(c(f"  ── SUMMARY ────────────────────────────────────────────────", CYAN))
#     print(f"  Files restored  : {c(str(ok_count), GREEN+BOLD)}")
#     print(f"  Failed          : {c(str(fail_count), RED if fail_count else DIM)}")
#     print(f"  Time elapsed    : {c(f'{elapsed:.2f}s', DIM)}")
#     if fail_count == 0:
#         print(c("\n  ✔ ALL FILES FULLY RESTORED — directory is clean.", GREEN+BOLD))
#     else:
#         print(c(f"\n  ⚠ {fail_count} file(s) could not be decrypted — key mismatch or corruption.", YELLOW))
#     print()


# def main():
#     parser = argparse.ArgumentParser(description="Project #11 — Ransomware Decryptor")
#     parser.add_argument("--dir",     default=str(DEFAULT_LAB_DIR),
#                         help=f"Lab directory (default: {DEFAULT_LAB_DIR})")
#     parser.add_argument("--dry-run", action="store_true",
#                         help="Preview what would be restored (no changes)")
#     args = parser.parse_args()
#     run_decryptor(Path(args.dir).expanduser().resolve(), args.dry_run)

# if __name__ == "__main__":
#     main()