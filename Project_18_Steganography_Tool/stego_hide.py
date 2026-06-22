#!/usr/bin/env python3
"""
==============================================================
  PROJECT #18 — Steganography Tool (Hide Data in Images)
  LSB Steganography with AES Encryption
==============================================================
"""

import argparse
import os
import sys
from PIL import Image
import struct
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Magic bytes for format identification
MAGIC_BYTES = b'STEGO_V1'
HEADER_FORMAT = '!8s I I'  # Magic(8) + DataLen(4) + EncryptedFlag(4)

class Steganography:
    def __init__(self):
        self.key = None
        
    def generate_key(self, password):
        """Generate encryption key from password"""
        try:
            # Updated PBKDF2 implementation
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'stego_salt_2024',
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            return Fernet(key)
        except Exception as e:
            # Fallback to simpler key derivation
            print(f"[!] Warning: Using simple encryption")
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            import hashlib
            key = hashlib.sha256(password.encode()).digest()
            key_b64 = base64.urlsafe_b64encode(key[:32])
            return Fernet(key_b64)
    
    def bytes_to_bits(self, data):
        """Convert bytes to bit string"""
        bits = []
        for byte in data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits
    
    def bits_to_bytes(self, bits):
        """Convert bit string to bytes"""
        bytes_data = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(bits):
                    byte = (byte << 1) | bits[i + j]
                else:
                    byte = byte << 1
            bytes_data.append(byte)
        return bytes(bytes_data)
    
    def hide_data(self, image_path, data_path, output_path, encrypt=False, password=None):
        """Hide data inside image"""
        print(f"\n{'='*60}")
        print(f"  Hiding Data in Image")
        print(f"{'='*60}")
        
        # Load image
        print(f"[*] Loading image: {image_path}")
        img = Image.open(image_path)
        
        # Convert to RGB if needed
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        pixels = list(img.getdata())
        width, height = img.size
        total_pixels = len(pixels)
        
        # Read data to hide
        print(f"[*] Reading data: {data_path}")
        with open(data_path, 'rb') as f:
            data = f.read()
        
        original_size = len(data)
        print(f"[*] Original data size: {original_size} bytes")
        
        # Encrypt if requested
        encrypted = False
        if encrypt:
            if not password:
                password = input("[?] Enter encryption password: ")
            fernet = self.generate_key(password)
            data = fernet.encrypt(data)
            encrypted = True
            print(f"[*] Encrypted data size: {len(data)} bytes")
        
        # Create header
        header = struct.pack(HEADER_FORMAT, MAGIC_BYTES, len(data), 1 if encrypted else 0)
        data_to_hide = header + data
        
        # Check capacity
        max_capacity = (total_pixels * 3) // 8
        required_bits = len(data_to_hide) * 8
        
        # Reserve 8 bytes for end marker
        required_bits += 32  # Add end marker
        
        if required_bits > total_pixels * 3:
            print(f"\n[!] ERROR: Data too large!")
            print(f"    Required: {required_bits} bits")
            print(f"    Capacity: {total_pixels * 3} bits")
            print(f"    Max file size: {max_capacity} bytes")
            print(f"    Your file: {len(data_to_hide)} bytes")
            return False
        
        print(f"[*] Required bits: {required_bits}")
        print(f"[*] Image capacity: {total_pixels * 3} bits")
        print(f"[*] Capacity usage: {(required_bits/(total_pixels*3))*100:.1f}%")
        
        # Add end marker (32 bits of 1s)
        end_marker = [1] * 32
        data_bits = self.bytes_to_bits(data_to_hide) + end_marker
        
        # Embed data
        print(f"[*] Embedding data...")
        new_pixels = []
        bit_index = 0
        
        for pixel in pixels:
            r, g, b = pixel
            
            if bit_index < len(data_bits):
                r = (r & 0xFE) | data_bits[bit_index]
                bit_index += 1
            
            if bit_index < len(data_bits):
                g = (g & 0xFE) | data_bits[bit_index]
                bit_index += 1
            
            if bit_index < len(data_bits):
                b = (b & 0xFE) | data_bits[bit_index]
                bit_index += 1
            
            new_pixels.append((r, g, b))
        
        # Fill remaining pixels
        while len(new_pixels) < total_pixels:
            new_pixels.append(pixels[len(new_pixels)])
        
        # Create new image
        print(f"[*] Creating output image: {output_path}")
        new_img = Image.new('RGB', (width, height))
        new_img.putdata(new_pixels)
        new_img.save(output_path)
        
        print(f"\n[✓] Success! Data hidden in {output_path}")
        print(f"    Original: {image_path}")
        print(f"    Data size: {original_size} bytes")
        print(f"    Encrypted: {encrypted}")
        
        return True
    
    def extract_data(self, image_path, output_path, password=None):
        """Extract hidden data from image"""
        print(f"\n{'='*60}")
        print(f"  Extracting Data from Image")
        print(f"{'='*60}")
        
        # Load image
        print(f"[*] Loading image: {image_path}")
        img = Image.open(image_path)
        
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        pixels = list(img.getdata())
        
        # Extract all LSBs
        print(f"[*] Extracting LSBs...")
        extracted_bits = []
        
        for pixel in pixels:
            r, g, b = pixel
            extracted_bits.append(r & 1)
            extracted_bits.append(g & 1)
            extracted_bits.append(b & 1)
        
        # Convert bits to bytes
        extracted_data = self.bits_to_bytes(extracted_bits)
        
        # Find magic bytes
        print(f"[*] Looking for magic bytes...")
        magic_pos = extracted_data.find(MAGIC_BYTES)
        
        if magic_pos == -1:
            print(f"[!] ERROR: No steganography data found!")
            print(f"[!] This image doesn't contain hidden data")
            return False
        
        # Parse header
        try:
            header_start = magic_pos
            header_end = header_start + struct.calcsize(HEADER_FORMAT)
            magic, data_len, encrypted = struct.unpack(HEADER_FORMAT, extracted_data[header_start:header_end])
            
            if magic != MAGIC_BYTES:
                print(f"[!] Invalid magic bytes!")
                return False
            
            print(f"[*] Found data - Size: {data_len} bytes, Encrypted: {bool(encrypted)}")
            
            # Extract actual data
            data_start = header_end
            data_end = data_start + data_len
            hidden_data = extracted_data[data_start:data_end]
            
            # Decrypt if needed
            if encrypted:
                if not password:
                    password = input("[?] Enter decryption password: ")
                fernet = self.generate_key(password)
                try:
                    hidden_data = fernet.decrypt(hidden_data)
                    print(f"[*] Decrypted data size: {len(hidden_data)} bytes")
                except Exception as e:
                    print(f"[!] Decryption failed: {e}")
                    return False
            
            # Save extracted data
            print(f"[*] Saving extracted data to: {output_path}")
            with open(output_path, 'wb') as f:
                f.write(hidden_data)
            
            print(f"\n[✓] Success! Data extracted to {output_path}")
            print(f"    Extracted size: {len(hidden_data)} bytes")
            
            return True
            
        except Exception as e:
            print(f"[!] Error extracting data: {e}")
            return False
    
    def check_capacity(self, image_path):
        """Check maximum capacity of image"""
        img = Image.open(image_path)
        
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        pixels = list(img.getdata())
        total_bits = len(pixels) * 3
        max_bytes = total_bits // 8
        
        print(f"\n{'='*60}")
        print(f"  Image Capacity Analysis")
        print(f"{'='*60}")
        print(f"Image: {image_path}")
        print(f"Dimensions: {img.size[0]} x {img.size[1]}")
        print(f"Total pixels: {len(pixels)}")
        print(f"Total bits available: {total_bits}")
        print(f"Maximum data size: {max_bytes} bytes ({max_bytes/1024:.2f} KB)")
        print(f"\nRecommended max data size: {int(max_bytes * 0.7)} bytes (70% for safety)")
        print(f"{'='*60}\n")
        
        return max_bytes

def main():
    parser = argparse.ArgumentParser(description="Steganography Tool")
    parser.add_argument("--input", help="Input carrier image")
    parser.add_argument("--data", help="Data file to hide")
    parser.add_argument("--output", help="Output image with hidden data")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt data before hiding")
    parser.add_argument("--extract", action="store_true", help="Extract mode")
    parser.add_argument("--check-capacity", action="store_true", help="Check image capacity")
    parser.add_argument("--password", help="Encryption password")
    
    args = parser.parse_args()
    
    stego = Steganography()
    
    # Check capacity mode
    if args.check_capacity:
        if not args.input:
            print("[-] Please specify --input image")
            sys.exit(1)
        stego.check_capacity(args.input)
        sys.exit(0)
    
    # Extract mode
    if args.extract:
        if not args.input or not args.output:
            print("[-] Please specify --input and --output for extraction")
            sys.exit(1)
        stego.extract_data(args.input, args.output, args.password)
        sys.exit(0)
    
    # Hide mode
    if not args.input or not args.data or not args.output:
        print("[-] Please specify --input, --data, and --output")
        print("\nUsage examples:")
        print("  Hide: python stego_hide.py --input cover.png --data secret.txt --output hidden.png")
        print("  Extract: python stego_hide.py --input hidden.png --output extracted.txt --extract")
        print("  Check capacity: python stego_hide.py --input cover.png --check-capacity")
        sys.exit(1)
    
    stego.hide_data(args.input, args.data, args.output, args.encrypt, args.password)

if __name__ == "__main__":
    main()