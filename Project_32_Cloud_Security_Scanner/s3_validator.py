#!/usr/bin/env python3
"""
Project #32 - Verified AWS S3 Posture Auditor (Real-World Interaction)
"""

import sys
import argparse
from datetime import datetime

try:
    import boto3
    from botocore import UNSIGNED
    from botocore.config import Config
    from botocore.exceptions import ClientError
except ImportError:
    print("[-] Dependency Missing: Run 'pip3 install boto3'")
    sys.exit(1)

# Colors
G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"; R = "\033[91m"; RESET = "\033[0m"

def audit_real_bucket(bucket_name):
    print(f"[*] Initializing real-world AWS API connection matrix...")
    
    # Configure Boto3 to make authentic, anonymous requests straight to real AWS S3 endpoints
    s3 = boto3.client('s3', config=Config(signature_version=UNSIGNED))
    
    print(f"[*] Dispatching live target query to AWS storage cloud: {C}s3://{bucket_name}{RESET}")
    print("-" * 75)

    findings = []
    bucket_exists = False
    public_read = False

    # 1. Test if the bucket actually exists on real AWS infrastructure
    try:
        s3.head_bucket(Bucket=bucket_name)
        print(f"  [{G}✓{RESET}] AWS Response: Bucket exists and is addressable.")
        bucket_exists = True
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == '404':
            print(f"  [{R}xx{RESET}] AWS Response: 404 Not Found (Bucket does not exist globally).")
            return
        elif error_code == '403':
            # 403 means it exists but requires valid AWS signatures to access metadata headers
            print(f"  [{G}✓{RESET}] AWS Response: 403 Forbidden (Bucket exists but metadata access is restricted).")
            bucket_exists = True
        else:
            print(f"  [-] Unexpected AWS API Exception: {e}")
            return

    # 2. Test for Public Read Access by attempting to list objects anonymously
    if bucket_exists:
        try:
            print(f"[*] Querying object namespace keys anonymously...")
            response = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=5)
            
            if 'Contents' in response:
                print(f"  [{R}💥{RESET}] {R}VULNERABILITY CONFIRMED: Public Read Access is ENABLED!{RESET}")
                public_read = True
                
                print(f"\n[+] Extracting sample live object listings from AWS response:")
                for obj in response['Contents']:
                    print(f"    └── File Key: {Y}{obj['Key']}{RESET} ({obj['Size']} bytes)")
                    
                    # Look for sensitive files in real data keys
                    lower_key = obj['Key'].lower()
                    if any(ext in lower_key for ext in ['.env', 'config.json', 'credential', '.pem']):
                        print(f"        {R}[!] SENSITIVE FILE LEAK PATTERN IDENTIFIED!{RESET}")
            else:
                print(f"  [{G}✓{RESET}] Bucket is structurally private (No public objects returned).")
        except ClientError as e:
            print(f"  [{G}✓{RESET}] Public Read Disabled: Object retrieval rejected by AWS S3 policy ({e.response['Error']['Code']}).")

    # Generate HTML report structure for supervisor evaluation
    generate_html_report(bucket_name, bucket_exists, public_read)

def generate_html_report(bucket, exists, is_public):
    status = "VULNERABLE" if is_public else "SECURE"
    details = "Exposed to the internet. Anonymous object listing allowed." if is_public else "Access Denied to anonymous users."
    
    html = f"""
    <html>
    <head><title>AWS S3 Production Audit Report</title></head>
    <body style="font-family:monospace; background:#111; color:#fff; padding:20px;">
        <h2>🎯 AWS S3 Verified Production Audit Report</h2>
        <p>Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <hr>
        <table border="1" style="border-collapse:collapse; width:100%; border-color:#333;">
            <tr style="background:#222;"><th>Target Bucket</th><th>Bucket Existence</th><th>Security Status</th><th>Details</th></tr>
            <tr><td>{bucket}</td><td>{'YES' if exists else 'NO'}</td><td style="color:{'red' if is_public else 'green'};">{status}</td><td>{details}</td></tr>
        </table>
    </body>
    </html>
    """
    with open("s3_production_audit.html", "w") as f:
        f.write(html)
    print(f"\n[+] Verified HTML audit profile exported successfully to: s3_production_audit.html")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bucket", required=True, help="Exact name of the real AWS S3 bucket to test")
    args = parser.parse_args()
    audit_real_bucket(args.bucket)
