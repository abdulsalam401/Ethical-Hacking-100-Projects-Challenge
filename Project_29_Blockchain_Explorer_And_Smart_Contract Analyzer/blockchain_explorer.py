#!/usr/bin/env python3
"""
PROJECT #29 — Blockchain Explorer & Smart Contract Analyzer
"""

import os
import sys
import json
import re
from datetime import datetime

# Try to import web3
try:
    from web3 import Web3
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False
    print("[!] web3 not installed. Run: pip3 install web3")

# Vulnerability patterns
PATTERNS = {
    "reentrancy": {
        "patterns": [r'call\{', r'\.transfer\(', r'\.send\('],
        "severity": "HIGH",
        "desc": "Potential reentrancy vulnerability",
        "score": 30
    },
    "unchecked_call": {
        "patterns": [r'\.send\([^;]*?\);'],
        "severity": "MEDIUM",
        "desc": "Unchecked external call",
        "score": 20
    },
    "timestamp": {
        "patterns": [r'block\.timestamp', r'now\s*[<>=]'],
        "severity": "MEDIUM",
        "desc": "Timestamp dependence",
        "score": 15
    },
    "overflow": {
        "patterns": [r'[a-zA-Z_][a-zA-Z0-9_]*\s*[\+\-\*]\s*[a-zA-Z_][a-zA-Z0-9_]*'],
        "severity": "HIGH",
        "desc": "Potential integer overflow",
        "score": 25
    }
}

class Explorer:
    def __init__(self, rpc_url, output="report.html"):
        self.rpc_url = rpc_url
        self.output = output
        self.w3 = None
        
    def connect(self):
        if not WEB3_AVAILABLE:
            return False
        try:
            self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            if self.w3.is_connected():
                print(f"[+] Connected! Chain ID: {self.w3.eth.chain_id}")
                return True
        except Exception as e:
            print(f"[-] Error: {e}")
        return False
    
    def get_transactions(self, address):
        print(f"\n[*] Fetching transactions for {address}")
        try:
            balance = self.w3.eth.get_balance(address)
            print(f"[+] Balance: {self.w3.from_wei(balance, 'ether'):.4f} ETH")
            
            txs = []
            latest = self.w3.eth.block_number
            found = 0
            
            for block_num in range(latest, max(0, latest - 500), -1):
                if found >= 20:
                    break
                try:
                    block = self.w3.eth.get_block(block_num, full_transactions=True)
                    for tx in block.transactions:
                        if tx['from'].lower() == address.lower() or (tx.get('to') and tx['to'].lower() == address.lower()):
                            txs.append({
                                'hash': tx['hash'].hex(),
                                'from': tx['from'],
                                'to': tx.get('to', 'Contract Creation'),
                                'value': self.w3.from_wei(tx.get('value', 0), 'ether'),
                                'block': block_num
                            })
                            found += 1
                except:
                    continue
            
            print(f"[+] Found {len(txs)} transactions")
            return txs
        except Exception as e:
            print(f"[-] Error: {e}")
            return []
    
    def analyze_contract(self, address):
        print(f"\n[*] Analyzing contract: {address}")
        try:
            code = self.w3.eth.get_code(address)
            if not code or code == b'' or code == b'0x':
                print("[!] Not a contract")
                return None
            
            print(f"[+] Bytecode size: {len(code)//2} bytes")
            
            code_str = code.hex().lower()
            findings = []
            risk = 0
            
            for name, info in PATTERNS.items():
                for pattern in info['patterns']:
                    if re.search(pattern, code_str):
                        findings.append({
                            'name': name,
                            'severity': info['severity'],
                            'desc': info['desc'],
                            'score': info['score']
                        })
                        risk += info['score']
                        break
            
            risk = min(risk, 100)
            level = "LOW" if risk == 0 else "MEDIUM" if risk < 30 else "HIGH" if risk < 60 else "CRITICAL"
            
            print(f"[+] Risk Score: {risk}/100 ({level})")
            if findings:
                print("[!] Vulnerabilities:")
                for f in findings:
                    print(f"  - {f['name']}: {f['desc']}")
            else:
                print("[✓] No vulnerabilities")
            
            return {
                'address': address,
                'findings': findings,
                'risk_score': risk,
                'risk_level': level
            }
        except Exception as e:
            print(f"[-] Error: {e}")
            return None
    
    def generate_report(self, address, txs, analysis):
        print(f"\n[*] Generating HTML report...")
        
        html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Blockchain Report</title>
<style>
body{{font-family:'Segoe UI',sans-serif;background:#1a1a2e;color:#e0e0e0;padding:20px;}}
.container{{max-width:1200px;margin:0 auto;}}
.header{{background:linear-gradient(135deg,#16213e,#0f3460);padding:30px;border-radius:10px;}}
.header h1{{color:#00d4ff;}}
.section{{background:#2d2d44;padding:20px;border-radius:10px;margin:15px 0;}}
.section h2{{color:#00d4ff;}}
table{{width:100%;border-collapse:collapse;}}
th,td{{padding:10px;text-align:left;border-bottom:1px solid #3d3d5a;}}
th{{color:#00d4ff;}}
.risk{{font-size:48px;font-weight:bold;text-align:center;padding:20px;}}
.risk-low{{color:#00ff88;}}
.risk-medium{{color:#ffa500;}}
.risk-high{{color:#ff4444;}}
.risk-critical{{color:#ff0040;}}
.vuln{{background:#2d2d44;padding:10px;margin:5px 0;border-radius:5px;border-left:4px solid #ff0040;}}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>🔍 Blockchain Explorer Report</h1>
<p>Address: {address}</p>
<p>Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</div>"""
        
        if txs:
            html += f"""
<div class="section">
<h2>📊 Transactions</h2>
<p>Total: {len(txs)}</p>
<table>
<tr><th>Hash</th><th>From</th><th>To</th><th>Value (ETH)</th></tr>"""
            for tx in txs[:15]:
                html += f"""
<tr>
<td style="font-size:12px;">{tx['hash'][:16]}...</td>
<td>{tx['from'][:16]}...</td>
<td>{str(tx['to'])[:16]}...</td>
<td>{tx['value']:.4f}</td>
</tr>"""
            html += "</table></div>"
        
        if analysis:
            risk = analysis['risk_level'].lower()
            html += f"""
<div class="section">
<h2>📝 Contract Analysis</h2>
<div class="risk risk-{risk}">{analysis['risk_score']}/100</div>
<p style="text-align:center;">Risk Level: <strong>{analysis['risk_level']}</strong></p>"""
            
            if analysis['findings']:
                html += "<h3>⚠️ Vulnerabilities</h3>"
                for f in analysis['findings']:
                    html += f"""
<div class="vuln">
<strong>{f['name']}</strong> - {f['desc']}
<br><span style="color:#888;">Severity: {f['severity']}</span>
</div>"""
            else:
                html += '<p style="color:#00ff88;">✅ No vulnerabilities</p>'
            html += "</div>"
        
        html += """
<div class="section">
<h3>🛡️ Defenses</h3>
<table>
<tr><th>Vulnerability</th><th>Defense</th></tr>
<tr><td>Reentrancy</td><td>Checks-Effects-Interactions</td></tr>
<tr><td>Unchecked Calls</td><td>Check return values</td></tr>
<tr><td>Timestamp</td><td>Avoid block.timestamp</td></tr>
<tr><td>Overflow</td><td>Use SafeMath</td></tr>
</table>
</div>
</div>
</body>
</html>"""
        
        with open(self.output, 'w') as f:
            f.write(html)
        print(f"[+] Report saved to {self.output}")
    
    def run(self, address=None, contract=None):
        print("\n" + "="*60)
        print("  PROJECT #29 — Blockchain Explorer")
        print("="*60)
        
        if not self.connect():
            print("[-] Failed to connect")
            return
        
        txs = []
        analysis = None
        
        if address:
            txs = self.get_transactions(address)
            # Check if address is a contract
            try:
                code = self.w3.eth.get_code(address)
                if code and code != b'' and code != b'0x':
                    analysis = self.analyze_contract(address)
            except:
                pass
        
        if contract:
            analysis = self.analyze_contract(contract)
        
        target = contract or address or "Unknown"
        self.generate_report(target, txs, analysis)

def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--address", help="Ethereum address")
    p.add_argument("--contract", help="Contract address")
    p.add_argument("--rpc", help="RPC URL", default="https://mainnet.infura.io/v3/demo")
    p.add_argument("--output", default="report.html")
    args = p.parse_args()
    
    if not args.address and not args.contract:
        print("[!] Specify --address or --contract")
        sys.exit(1)
    
    e = Explorer(args.rpc, args.output)
    e.run(args.address, args.contract)

if __name__ == "__main__":
    main()