# # decode_payload.py
# import base64
# import sys

# XOR_KEY = "ultraprohacker"

# def xor_bytes(data: bytes, key: str) -> bytes:
#     kb = key.encode()
#     kl = len(kb)
#     return bytes(b ^ kb[i % kl] for i, b in enumerate(data))

# def deobfuscate(b64: str) -> str:
#     enc = base64.b64decode(b64.encode())
#     raw = xor_bytes(enc, XOR_KEY)
#     return raw.decode("utf-8", errors="replace")

# if __name__ == "__main__":
#     if len(sys.argv) > 1:
#         # Decode from command line argument
#         result = deobfuscate(sys.argv[1])
#         print(result)
#     else:
#         # Interactive mode
#         print("Paste the obfuscated payload (or press Ctrl+D to finish):")
#         lines = []
#         try:
#             while True:
#                 line = input()
#                 lines.append(line)
#         except EOFError:
#             pass
        
#         payload = ''.join(lines).strip()
#         if payload:
#             result = deobfuscate(payload)
#             print("\n" + "="*60)
#             print("DECODED TEXT:")
#             print("="*60)
#             print(result)
#             print("="*60)

# decode_simple.py
import base64

XOR_KEY = "ultraprohacker"

def decode_payload(encoded):
    decoded = base64.b64decode(encoded)
    key_bytes = XOR_KEY.encode()
    result = bytes([decoded[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(decoded))])
    return result.decode('utf-8', errors='ignore')

# Paste the encoded payload from email (the long base64 string)
encoded = input("Paste the encoded payload: ").strip()
print("\n" + "="*60)
print("DECODED KEYSTROKES:")
print("="*60)
print(decode_payload(encoded))
print("="*60)