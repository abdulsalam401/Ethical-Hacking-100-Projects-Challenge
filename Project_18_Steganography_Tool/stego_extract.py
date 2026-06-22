#!/usr/bin/env python3
"""
==============================================================
  PROJECT #18 — Steganography Tool (Extract Data)
  Extract hidden data from stego images
==============================================================

USAGE:
--------
  python stego_extract.py --input hidden.png --output extracted.txt
  
  # With password (if encrypted)
  python stego_extract.py --input hidden.png --output extracted.txt --password mypass
==============================================================
"""

import argparse
import sys
from stego_hide import Steganography

def main():
    parser = argparse.ArgumentParser(description="Extract hidden data from stego image")
    parser.add_argument("--input", required=True, help="Stego image with hidden data")
    parser.add_argument("--output", required=True, help="Output file for extracted data")
    parser.add_argument("--password", help="Decryption password")
    
    args = parser.parse_args()
    
    stego = Steganography()
    
    try:
        success = stego.extract_data(args.input, args.output, args.password)
        if success:
            print(f"\n[✓] Extraction complete!")
        else:
            print(f"\n[!] Extraction failed!")
            sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()