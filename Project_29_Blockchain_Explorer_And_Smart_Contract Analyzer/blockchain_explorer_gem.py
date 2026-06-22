#!/usr/bin/env python3
"""
Project #29: Blockchain Explorer & Heuristic EVM Smart Contract Analyzer
Architecture: Web3 Node Interaction API + Low-Level Bytecode Heuristic Scanning.
"""

import sys
import json
import argparse
from web3 import Web3

# Terminal Color Palette
G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"; R = "\033[91m"; BOLD = "\033[1m"; RESET = "\033[0m"

BANNER = """
======================================================================
  BLOCKCHAIN CORE: LIQUIDITY EXPLORER & EVM BYTECODE RISK AUDITOR
======================================================================
"""

# Public resilient Ethereum RPC gateway fallback endpoint
PUBLIC_RPC = "https://rpc.ankr.com/eth"
# Change this line from the public node to your custom Infura URL

PUBLIC_RPC = "https://mainnet.infura.io/v3/9af0da85f6ba49cfaeb3eaeca143375b"

def analyze_contract_bytecode(bytecode_hex: str) -> dict:
    """Performs static heuristic signature checking over compiled EVM instructions."""
    findings = []
    risk_score = 0
    
    bytecode = bytecode_hex.lower()
    if bytecode.startswith("0x"):
        bytecode = bytecode[2:]
        
    if not bytecode or bytecode == "0x" or bytecode == "":
        return {"risk_score": 0, "findings": ["Null Bytecode: Target is a standard EOA account, not a contract."]}

    # --- 1. REENTRANCY HEURISTIC DETECTOR ---
    if "f1" in bytecode and "55" in bytecode:
        if bytecode.find("f1") < bytecode.find("55"):
            findings.append("CRITICAL: Potential Reentrancy Flaw (External CALL executes prior to internal SSTORE state mutation).")
            risk_score += 45

    # --- 2. TIMESTAMP DEPENDENCE DETECTOR ---
    if "42" in bytecode:
        findings.append("WARNING: Timestamp Dependence Located (Opcode 0x42: Uses block.timestamp for critical control routing).")
        risk_score += 20

    # --- 3. UNCHECKED EXTERNAL CALLS DETECTOR ---
    if "f1" in bytecode and "57" not in bytecode[bytecode.find("f1"):bytecode.find("f1")+20]:
        findings.append("MEDIUM: Unchecked External Call (Potential lack of explicit return value verification after call stream).")
        risk_score += 25

    # --- 4. ARITHMETIC SAFETY OVERVIEW ---
    if "02" in bytecode or "03" in bytecode:
        if "fe" not in bytecode:
            findings.append("LOW: Legacy Arithmetic Pipeline (Ensure integer overflow protections are compiled explicitly).")
            risk_score += 10

    risk_score = min(risk_score, 100)
    return {
        "risk_score": risk_score,
        "findings": findings if findings else ["No high-severity heuristic bytecode anti-patterns identified."]
    }

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="EVM Blockchain Auditing Framework")
    parser.add_argument("--address", help="Target ledger account address to inspect (EOA or Contract)")
    parser.add_argument("--contract", action="store_true", help="Enforce static EVM runtime bytecode heuristic scan")
    args = parser.parse_args()

    target_address = args.address if args.address else "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

    print(f"[*] Connecting to decentralized network node architecture at: {PUBLIC_RPC}")
    w3 = Web3(Web3.HTTPProvider(PUBLIC_RPC))

    # Graceful connectivity evaluation check
    try:
        connected = w3.is_connected()
    except Exception:
        connected = False

    if not connected:
        print(f"{Y}[!] Warning: Unable to sync with live RPC endpoint. Operating in Offline/Simulation Mode.{RESET}")
        w3 = None

    if w3 and not w3.is_address(target_address):
        print(f"{R}[!] Input Parameter Error: Address string '{target_address}' violates hex formatting rules.{RESET}")
        sys.exit(1)
        
    checksum_address = w3.to_checksum_address(target_address) if w3 else target_address
    print(f"[*] Fetching ledger metrics for target token space: {C}{checksum_address}{RESET}")

    balance_eth = 0.0
    bytecode = "0x"

    # Encapsulate live requests inside try-except scopes to bypass remote node drop errors
    if w3:
        try:
            balance_wei = w3.eth.get_balance(checksum_address)
            balance_eth = w3.from_wei(balance_wei, 'ether')
            bytecode = w3.eth.get_code(checksum_address).hex()
        except Exception as e:
            print(f"{Y}[!] Live state fetch failed ({e}). Reverting to core SAST checking loop.{RESET}")
            bytecode = "0x"

    print(f"   👉 Core Native Balance: {G}{balance_eth:.4f} ETH{RESET}")

    if bytecode == "0x" or not bytecode:
        if args.contract:
            print(f"   👉 Node Account Status: {G}Smart Contract Analysis Explicitly Requested.{RESET}")
        else:
            print(f"   👉 Node Account Status: {Y}Externally Owned Account (EOA User Wallet - No Code deployed){RESET}")

    # 3. Handle Active Auditing Analysis Request Routines
    if args.contract or bytecode != "0x":
        print(f"\n{BOLD}[*] Initializing EVM SAST Static Code Audit Engine...{RESET}")
        print("-" * 75)
        
        if bytecode == "0x" or not bytecode:
            print(f"{Y}[*] Injecting reference vulnerable contract bytecode matrix for validation check...{RESET}")
            # Reference vulnerable code sequence: CALL (f1) before SSTORE (55) along with TIMESTAMP (42)
            bytecode = "6060604052341561000c57fe5b5b4260005530f15500"

        audit_results = analyze_contract_bytecode(bytecode)
        score = audit_results["risk_score"]
        color_flag = G if score < 30 else (Y if score < 60 else R)
        
        print(f"{BOLD}CONTRACT SECURITY PROFILE REPORT:{RESET}")
        print(f"┌────────────────────────────────────────────────────────────────────┐")
        print(f"│  OVERALL SECURITY RISK SCORE:   {color_flag}{str(score).ljust(3)} / 100{RESET}                                │")
        print(f"└────────────────────────────────────────────────────────────────────┘")
        
        print(f"\n{BOLD}HEURISTIC VULNERABILITY FINDINGS MATRIX:{RESET}")
        for finding in audit_results["findings"]:
            if "CRITICAL" in finding:
                print(f"  [{R}💥{RESET}] {R}{finding}{RESET}")
            elif "WARNING" in finding:
                print(f"  [{Y}⚠️{RESET}] {Y}{finding}{RESET}")
            else:
                print(f"  [{C}🔹{RESET}] {finding}")
        print("-" * 75)

if __name__ == "__main__":
    main()
