#!/usr/bin/env python3
import base64

XOR_KEY = "ultraprohacker"

def deobfuscate(b64: str) -> str:
    enc = base64.b64decode(b64.encode())
    kb = XOR_KEY.encode()
    kl = len(kb)
    raw = bytes(enc[i] ^ kb[i % kl] for i in range(len(enc)))
    return raw.decode("utf-8", errors="replace")

# PASTE THE EXACT OBFUSCATED STRING FROM YOUR EMAIL HERE:
test_b64 = "f1FJT1xNT1JVXF5WWE9IUUlPXE1PUlVcXlZYT0hRSU9cTU9SVVxeVlhPSFFJT1xNT2U7JDA4LD07VlRAUUJEQlhXTltSUkRfTkZUSkBdYiksODFIVSgxISokPT9FWCItVCJAXFRSLiNITz8IDQ8KBQZmSU9cTU9SVVxeVlhPSFFJT1xNT1JVXF5WWE9IUUlPXE1PUlVcXlZYT0hRSU9cTU9SYgkGBwoFEAQdUgwJUgEJBEMCFlJ/UUlPXE1PUlVcXlZYT0hRSU9cTU9SVVxeVlhPSFFJT1xNT1JVXF5WWE9IUUlPXE1PZS0vJ0sqNFU/MSEyOT0hSIPj/0VDTEwfFxgDBh0HCgYYb09IUUlPXE1PUlVcXlZYT0hRSU9cTU9SVVxeVlhPSFFJT1xNT1JVXF5WWE9IUUlPXHo"

print("=== DECODED ===")
print(repr(deobfuscate(test_b64)))