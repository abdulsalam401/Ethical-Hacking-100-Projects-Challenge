#!/usr/bin/env python3
"""
Project #35: Cross-Platform Binary Static Vulnerability Auditor (PE / ELF)
Architecture: Static Structural Parsing via pefile & pyelftools + Entropy Metrics.
"""

import os
import sys
import math
import argparse
from datetime import datetime

# Import wrappers safely
try:
    import pefile
except ImportError:
    pass

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import NoteSection
except ImportError:
    pass

# UI Palettes
G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"; R = "\033[91m"; BOLD = "\033[1m"; RESET = "\033[0m"

BANNER = """
======================================================================
  🛡️  BINARY AUDITOR: CROSS-PLATFORM STATIC PARSING ENGINE
======================================================================
"""

def calculate_section_entropy(data):
    """Computes Shannon Entropy to evaluate obfuscation or packing indicator metrics."""
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def analyze_pe(file_path):
    """Parses Portable Executable headers to extract exploit mitigation states."""
    print(f"[\033[92m✓\033[0m] Magic Bytes Match: Windows PE Format Detected.")
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        print(f"\033[91m[!] pefile processing error: {e}\033[0m")
        return None

    report = {
        "format": "Windows PE",
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "sections": [],
        "imports": [],
        "security": {"ASLR": False, "DEP": False, "StackCanary": False}
    }

    # Evaluate Security Mitigation Flags inside Optional Headers
    dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
    
    if dll_characteristics & 0x0040:  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        report["security"]["ASLR"] = True
    if dll_characteristics & 0x0100:  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        report["security"]["DEP"] = True

    # Check for Stack Cookies via Load Configuration Directory availability
    pe.parse_data_directories()
    if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
        lc = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
        if hasattr(lc, 'SecurityCookie') and lc.SecurityCookie != 0:
            report["security"]["StackCanary"] = True

    # Extract Memory Sections Profiles & Entropy Values
    for section in pe.sections:
        try:
            s_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        except:
            s_name = "unknown"
        s_size = section.SizeOfRawData
        s_data = section.get_data()
        s_entropy = calculate_section_entropy(s_data)
        
        report["sections"].append({
            "name": s_name,
            "size": s_size,
            "entropy": round(s_entropy, 2)
        })

    # Extract Core System API Imports Table Directory
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    if imp.name:
                        report["imports"].append(f"{dll_name}!{imp.name.decode('utf-8', errors='ignore')}")
            except:
                pass

    return report

def analyze_elf(file_path):
    """Parses Executable and Linkable Format structural program headers."""
    print(f"[\033[92m✓\033[0m] Magic Bytes Match: Linux ELF Format Detected.")
    
    report = {
        "format": "Linux ELF",
        "entry_point": "0x0",
        "sections": [],
        "imports": [],
        "security": {"ASLR": False, "DEP": False, "StackCanary": False}
    }

    with open(file_path, 'rb') as f:
        try:
            elffile = ELFFile(f)
            report["entry_point"] = hex(elffile.header['e_entry'])

            # Parse Segment Program Headers for Security Controls
            for segment in elffile.iter_segments():
                if segment.header['p_type'] == 'PT_GNU_RELRO':
                    report["security"]["ASLR"] = True 
                if segment.header['p_type'] == 'PT_GNU_STACK':
                    if not (segment.header['p_flags'] & 1): # 1 = PF_X (Execute flag)
                        report["security"]["DEP"] = True

            # Extract Sections & Local Entropy Markers
            for section in elffile.iter_sections():
                if section.is_null():
                    continue
                s_name = section.name
                s_size = section.header['sh_size']
                s_data = section.data()
                s_entropy = calculate_section_entropy(s_data)

                report["sections"].append({
                    "name": s_name,
                    "size": s_size,
                    "entropy": round(s_entropy, 2)
                })

            # Canary detection via Symbol Table lookups
            symbol_sec = elffile.get_section_by_name('.symtab')
            if symbol_sec:
                for symbol in symbol_sec.iter_symbols():
                    if '__stack_chk_fail' in symbol.name:
                        report["security"]["StackCanary"] = True

        except Exception as e:
            print(f"\033[91m[!] elftools processing error: {e}\033[0m")
            return None

    return report

def generate_html(report, out_file):
    """Compiles findings into a static forensic report table layout."""
    score = 100
    deductions = []
    
    for key, val in report["security"].items():
        if not val:
            score -= 30
            deductions.append(f"Missing {key} compiler protection flag allocation.")

    html = f"""
    <html>
    <head><title>Static Binary Risk Audit</title><style>body{{font-family:sans-serif;background:#1a1a1a;color:#eee;padding:20px;}}th,td{{padding:8px;border:1px solid #444;text-align:left;}}table{{width:100%;border-collapse:collapse;}}</style></head>
    <body>
        <h2>🛡️ Production Static Binary Analysis Framework</h2>
        <p><b>Timestamp:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | <b>Binary Format:</b> {report['format']}</p>
        <hr style="border-color:#444;">
        <h3>Calculated Safety Risk Score: <span style="color:{'green' if score > 50 else 'red'};">{score}/100</span></h3>
        
        <h4>1. Exploitation Mitigation Matrix Flags</h4>
        <table>
            <tr style="background:#222;"><th>Mitigation Feature</th><th>Status Condition</th></tr>
            <tr><td>ASLR (Randomized Base Address)</td><td>{"ENABLED (Secure)" if report['security']['ASLR'] else "DISABLED (Vulnerable)"}</td></tr>
            <tr><td>DEP / NX (Non-Executable Memory Protection)</td><td>{"ENABLED (Secure)" if report['security']['DEP'] else "DISABLED (Vulnerable)"}</td></tr>
            <tr><td>Stack Canary (Buffer Overflow Guard)</td><td>{"ENABLED (Secure)" if report['security']['StackCanary'] else "DISABLED (Vulnerable)"}</td></tr>
        </table>
    """
    
    if deductions:
        html += "<h4>⚠️ Critical Security Anomalies Noted:</h4><ul>"
        for d in deductions:
            html += f"<li style='color:orange;'>{d}</li>"
        html += "</ul>"

    html += f"""
        <h4>2. Binary Section Analysis Details</h4>
        <table>
            <tr style="background:#222;"><th>Section Name</th><th>Raw Section Size (Bytes)</th><th>Section Data Entropy Value (0-8)</th></tr>
    """
    for s in report["sections"]:
        alert = "style='color:red; font-weight:bold;'" if s["entropy"] > 7.0 else ""
        html += f"<tr><td>{s['name']}</td><td>{s['size']}</td><td {alert}>{s['entropy']}</td></tr>"
        
    html += "</table></body></html>"

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n[+] Production risk matrix report compiled inside: \033[92m{out_file}\033[0m\n")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Cross-Platform Cross-Architecture Binary Guard Utility")
    parser.add_argument("--file", required=True, help="Path to targeted input program file block asset")
    parser.add_argument("--output", default="binary_audit_report.html", help="Path to compilation output file")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"\033[91m[!] File asset targets not found: {args.file}\033[0m")
        return

    # Direct Magic Bytes Header Identification
    with open(args.file, "rb") as f:
        magic = f.read(4)

    report = None
    if magic.startswith(b'MZ'):
        report = analyze_pe(args.file)
    elif magic.startswith(b'\x7fELF'):
        report = analyze_elf(args.file)
    else:
        print(f"\033[91m[!] Analysis Blocked: Asset magic byte header format signature unrecognizable.\033[0m")
        return

    if report:
        generate_html(report, args.output)

if __name__ == "__main__":
    main()
