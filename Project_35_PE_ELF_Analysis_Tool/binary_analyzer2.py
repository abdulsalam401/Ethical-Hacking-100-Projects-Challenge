#!/usr/bin/env python3
"""
PROJECT #35 — PE/ELF Analysis Tool (Fixed)
"""

import os
import sys
import struct
import hashlib
import math
from datetime import datetime

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; MAGENTA=''; WHITE=''
        LIGHTBLACK_EX=''; LIGHTRED_EX=''; LIGHTGREEN_EX=''; LIGHTYELLOW_EX=''
        LIGHTBLUE_EX=''; LIGHTMAGENTA_EX=''; LIGHTCYAN_EX=''
    class Style:
        BRIGHT=''; DIM=''; RESET_ALL=''

class Colors:
    HEADER = Fore.CYAN + Style.BRIGHT
    OKBLUE = Fore.BLUE + Style.BRIGHT
    OKGREEN = Fore.GREEN + Style.BRIGHT
    WARNING = Fore.YELLOW + Style.BRIGHT
    FAIL = Fore.RED + Style.BRIGHT
    ENDC = Style.RESET_ALL
    BOLD = Style.BRIGHT
    DIM = Fore.LIGHTBLACK_EX
    MAGENTA = Fore.MAGENTA + Style.BRIGHT

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    print(f"{Colors.FAIL}[-] pefile not installed. Run: pip install pefile{Colors.ENDC}")

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    ELFTOOLS_AVAILABLE = True
except ImportError:
    ELFTOOLS_AVAILABLE = False
    print(f"{Colors.FAIL}[-] pyelftools not installed. Run: pip install pyelftools{Colors.ENDC}")

class BinaryAnalyzer:
    def __init__(self, filepath, output_file="binary_report.html", verbose=False):
        self.filepath = filepath
        self.output_file = output_file
        self.verbose = verbose
        self.file_type = None
        self.pe = None
        self.elf = None
        self.findings = []
        self.risk_score = 0
        self.info = {}
        
    def detect_file_type(self):
        with open(self.filepath, 'rb') as f:
            magic = f.read(4)
        if magic.startswith(b'MZ'):
            self.file_type = 'PE'
            return True
        elif magic.startswith(b'\x7fELF'):
            self.file_type = 'ELF'
            return True
        else:
            return False
    
    def analyze_pe(self):
        print(f"{Colors.OKBLUE}[*] Analyzing PE file...{Colors.ENDC}")
        
        if not PEFILE_AVAILABLE:
            print(f"{Colors.FAIL}[-] pefile not available{Colors.ENDC}")
            return
        
        try:
            self.pe = pefile.PE(self.filepath)
            
            # Basic Info
            self.info['file_type'] = 'PE'
            self.info['machine'] = hex(self.pe.FILE_HEADER.Machine)
            self.info['number_of_sections'] = self.pe.FILE_HEADER.NumberOfSections
            self.info['entry_point'] = hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            self.info['image_base'] = hex(self.pe.OPTIONAL_HEADER.ImageBase)
            self.info['size_of_image'] = self.pe.OPTIONAL_HEADER.SizeOfImage
            
            # Sections
            sections = []
            for section in self.pe.sections:
                sections.append({
                    'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    'virtual_size': section.Misc_VirtualSize,
                    'virtual_address': hex(section.VirtualAddress),
                    'raw_size': section.SizeOfRawData
                })
            self.info['sections'] = sections
            
            # Imports
            imports = []
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    functions = []
                    for imp in entry.imports:
                        if imp.name:
                            functions.append(imp.name.decode('utf-8', errors='ignore'))
                    imports.append({
                        'dll': dll_name,
                        'functions': functions[:10]
                    })
            self.info['imports'] = imports
            
            # Exports
            exports = []
            if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    exports.append(exp.name.decode('utf-8', errors='ignore') if exp.name else 'Ordinal')
            self.info['exports'] = exports[:20]
            
            # Security checks
            self.check_pe_security()
            
        except Exception as e:
            print(f"{Colors.FAIL}[-] Error analyzing PE: {e}{Colors.ENDC}")
    
    def check_pe_security(self):
        """Check PE for security issues"""
        print(f"{Colors.OKBLUE}[*] Checking security features...{Colors.ENDC}")
        
        # Get DllCharacteristics
        dll_char = self.pe.OPTIONAL_HEADER.DllCharacteristics
        
        # 1. ASLR (DYNAMIC_BASE) - value 0x40
        if dll_char & 0x40:  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            print(f"{Colors.OKGREEN}[✓] ASLR enabled (DYNAMIC_BASE){Colors.ENDC}")
        else:
            self.findings.append({
                'severity': 'HIGH',
                'type': 'ASLR_DISABLED',
                'description': 'ASLR (Address Space Layout Randomization) is disabled',
                'recommendation': 'Enable /DYNAMICBASE linker flag'
            })
            self.risk_score += 25
            print(f"{Colors.FAIL}[✗] ASLR disabled{Colors.ENDC}")
        
        # 2. DEP (NX_COMPAT) - value 0x100
        if dll_char & 0x100:  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
            print(f"{Colors.OKGREEN}[✓] DEP enabled (NX_COMPAT){Colors.ENDC}")
        else:
            self.findings.append({
                'severity': 'HIGH',
                'type': 'DEP_DISABLED',
                'description': 'DEP (Data Execution Prevention) is disabled',
                'recommendation': 'Enable /NXCOMPAT linker flag'
            })
            self.risk_score += 25
            print(f"{Colors.FAIL}[✗] DEP disabled{Colors.ENDC}")
        
        # 3. Stack Cookie (GS) - check for __security_check_cookie
        stack_cookie = False
        try:
            for section in self.pe.sections:
                if section.Name.startswith(b'.text'):
                    data = section.get_data()
                    if b'__security_check_cookie' in data or b'__GSHandlerCheck' in data:
                        stack_cookie = True
                        print(f"{Colors.OKGREEN}[✓] Stack cookie detected{Colors.ENDC}")
                        break
        except:
            pass
        
        if not stack_cookie:
            self.findings.append({
                'severity': 'MEDIUM',
                'type': 'STACK_COOKIE_MISSING',
                'description': 'Stack cookie (/GS) not detected',
                'recommendation': 'Enable /GS linker flag'
            })
            self.risk_score += 15
            print(f"{Colors.FAIL}[✗] Stack cookie missing{Colors.ENDC}")
        
        # 4. Code Signing
        signed = False
        if hasattr(self.pe, 'DIRECTORY_ENTRY_SECURITY'):
            signed = True
            print(f"{Colors.OKGREEN}[✓] Code signing detected{Colors.ENDC}")
        else:
            self.findings.append({
                'severity': 'MEDIUM',
                'type': 'CODE_SIGNING_MISSING',
                'description': 'Code signing not detected',
                'recommendation': 'Sign the binary with a certificate'
            })
            self.risk_score += 10
            print(f"{Colors.FAIL}[✗] Code signing missing{Colors.ENDC}")
        
        # 5. High entropy sections (packing detection)
        for section in self.pe.sections:
            data = section.get_data()
            if data and len(data) > 100:
                entropy = self.calculate_entropy(data)
                if entropy > 7.0:
                    self.findings.append({
                        'severity': 'LOW',
                        'type': 'HIGH_ENTROPY',
                        'description': f'Section {section.Name.decode().strip()} has high entropy ({entropy:.2f}) - possible packing',
                        'recommendation': 'Investigate if packing is intentional'
                    })
                    self.risk_score += 5
                    print(f"{Colors.WARNING}[!] High entropy section: {section.Name.decode().strip()} ({entropy:.2f}){Colors.ENDC}")
                    break
        
        # 6. SafeSEH - value 0x400
        if dll_char & 0x400:  # IMAGE_DLLCHARACTERISTICS_SAFE_SEH
            print(f"{Colors.OKGREEN}[✓] SafeSEH enabled{Colors.ENDC}")
        else:
            self.findings.append({
                'severity': 'LOW',
                'type': 'SAFESEH_DISABLED',
                'description': 'SafeSEH not enabled',
                'recommendation': 'Enable /SAFESEH linker flag'
            })
            self.risk_score += 5
            print(f"{Colors.FAIL}[✗] SafeSEH disabled{Colors.ENDC}")
        
        # 7. Control Flow Guard - value 0x4000
        if dll_char & 0x4000:  # IMAGE_DLLCHARACTERISTICS_GUARD_CF
            print(f"{Colors.OKGREEN}[✓] Control Flow Guard enabled{Colors.ENDC}")
        else:
            self.findings.append({
                'severity': 'LOW',
                'type': 'CFG_DISABLED',
                'description': 'Control Flow Guard not enabled',
                'recommendation': 'Enable /GUARD:CF linker flag'
            })
            self.risk_score += 5
            print(f"{Colors.FAIL}[✗] CFG disabled{Colors.ENDC}")
    
    def analyze_elf(self):
        """Analyze ELF file"""
        print(f"{Colors.OKBLUE}[*] Analyzing ELF file...{Colors.ENDC}")
        
        if not ELFTOOLS_AVAILABLE:
            return
        
        try:
            with open(self.filepath, 'rb') as f:
                self.elf = ELFFile(f)
                
                self.info['file_type'] = 'ELF'
                self.info['elf_class'] = 'ELF32' if self.elf.elfclass == 32 else 'ELF64'
                self.info['machine'] = self.elf.header.e_machine
                self.info['entry_point'] = hex(self.elf.header.e_entry)
                self.info['number_of_sections'] = self.elf.num_sections()
                
                # Sections
                sections = []
                for section in self.elf.iter_sections():
                    sections.append({
                        'name': section.name,
                        'size': section.data_size,
                        'address': hex(section.header.sh_addr)
                    })
                self.info['sections'] = sections[:20]
                
                # Imports
                imports = []
                try:
                    dyn_section = self.elf.get_section_by_name('.dynamic')
                    if dyn_section:
                        for tag in dyn_section.iter_tags():
                            if tag.entry.d_tag == 'DT_NEEDED':
                                imports.append(tag.needed)
                except:
                    pass
                self.info['imports'] = imports
                
                self.check_elf_security()
                
        except Exception as e:
            print(f"{Colors.FAIL}[-] Error analyzing ELF: {e}{Colors.ENDC}")
    
    def check_elf_security(self):
        print(f"{Colors.OKBLUE}[*] Checking security features...{Colors.ENDC}")
        
        # RELRO
        relro_found = False
        for section in self.elf.iter_sections():
            if section.name and ('relro' in section.name.lower() or 'rel.ro' in section.name.lower()):
                relro_found = True
                print(f"{Colors.OKGREEN}[✓] RELRO found{Colors.ENDC}")
                break
        
        if not relro_found:
            self.findings.append({
                'severity': 'HIGH',
                'type': 'RELRO_MISSING',
                'description': 'RELRO (Relocation Read-Only) not enabled',
                'recommendation': 'Use -Wl,-z,relro,-z,now linker flags'
            })
            self.risk_score += 25
            print(f"{Colors.FAIL}[✗] RELRO missing{Colors.ENDC}")
        
        # NX
        nx_found = False
        for section in self.elf.iter_sections():
            if section.name and '.got' in section.name:
                nx_found = True
                break
        
        if nx_found:
            print(f"{Colors.OKGREEN}[✓] NX (non-executable stack) likely enabled{Colors.ENDC}")
        else:
            self.findings.append({
                'severity': 'HIGH',
                'type': 'NX_DISABLED',
                'description': 'NX (non-executable stack) not detected',
                'recommendation': 'Use -z noexecstack linker flag'
            })
            self.risk_score += 25
            print(f"{Colors.FAIL}[✗] NX disabled{Colors.ENDC}")
        
        # PIE
        pie_found = False
        for section in self.elf.iter_sections():
            if section.name and ('.dynamic' in section.name or '.got' in section.name):
                pie_found = True
                break
        
        if pie_found:
            print(f"{Colors.OKGREEN}[✓] PIE (Position Independent Executable) likely enabled{Colors.ENDC}")
        else:
            self.findings.append({
                'severity': 'HIGH',
                'type': 'PIE_DISABLED',
                'description': 'PIE (Position Independent Executable) not detected',
                'recommendation': 'Use -fPIE -pie compiler flags'
            })
            self.risk_score += 20
            print(f"{Colors.FAIL}[✗] PIE disabled{Colors.ENDC}")
        
        # Stack canary
        stack_canary = False
        for section in self.elf.iter_sections():
            if section.name and '.text' in section.name:
                data = section.data()
                if data and b'__stack_chk_fail' in data:
                    stack_canary = True
                    print(f"{Colors.OKGREEN}[✓] Stack canary detected{Colors.ENDC}")
                    break
        
        if not stack_canary:
            self.findings.append({
                'severity': 'MEDIUM',
                'type': 'STACK_CANARY_MISSING',
                'description': 'Stack canary not detected',
                'recommendation': 'Use -fstack-protector-strong compiler flag'
            })
            self.risk_score += 15
            print(f"{Colors.FAIL}[✗] Stack canary missing{Colors.ENDC}")
    
    def calculate_entropy(self, data):
        if not data:
            return 0
        frequency = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1
        entropy = 0
        length = len(data)
        for count in frequency.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return entropy
    
    def run_analysis(self):
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}  PROJECT #35 — PE/ELF Analysis Tool{Colors.ENDC}")
        print(f"{Colors.OKBLUE}  Static Binary Analyzer{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        print(f"{Colors.OKGREEN}[+] File: {self.filepath}{Colors.ENDC}")
        
        if not os.path.exists(self.filepath):
            print(f"{Colors.FAIL}[-] File not found{Colors.ENDC}")
            return
        
        if not self.detect_file_type():
            print(f"{Colors.FAIL}[-] Unknown file type (not PE or ELF){Colors.ENDC}")
            return
        
        print(f"{Colors.OKGREEN}[+] File type: {self.file_type}{Colors.ENDC}")
        
        if self.file_type == 'PE':
            self.analyze_pe()
        else:
            self.analyze_elf()
        
        self.generate_report()
    
    def generate_report(self):
        print(f"\n{Colors.OKBLUE}[*] Generating HTML report...{Colors.ENDC}")
        
        if self.risk_score >= 70:
            risk_level, risk_color = "CRITICAL", "#ff0040"
        elif self.risk_score >= 50:
            risk_level, risk_color = "HIGH", "#ff4444"
        elif self.risk_score >= 30:
            risk_level, risk_color = "MEDIUM", "#ffa500"
        else:
            risk_level, risk_color = "LOW", "#00ff88"
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Binary Analysis Report</title>
    <style>
        body {{font-family:'Segoe UI',sans-serif;background:#1a1a2e;color:#e0e0e0;padding:20px;}}
        .container {{max-width:1200px;margin:0 auto;}}
        .header {{background:linear-gradient(135deg,#16213e,#0f3460);padding:30px;border-radius:10px;}}
        .header h1 {{color:#00d4ff;}}
        .risk-score {{font-size:48px;font-weight:bold;text-align:center;padding:20px;}}
        .risk-low {{color:#00ff88;}}
        .risk-medium {{color:#ffa500;}}
        .risk-high {{color:#ff4444;}}
        .risk-critical {{color:#ff0040;}}
        .section {{background:#2d2d44;padding:20px;border-radius:10px;margin:15px 0;}}
        .section h2 {{color:#00d4ff;border-bottom:1px solid #3d3d5a;padding-bottom:10px;}}
        .stat-box {{display:inline-block;background:#1a1a3e;padding:15px;border-radius:8px;margin:5px;min-width:150px;}}
        .stat-box .value {{font-size:24px;font-weight:bold;color:#00d4ff;}}
        .stat-box .label {{color:#888;font-size:12px;}}
        .finding {{background:#2d2d44;padding:15px;margin:10px 0;border-radius:8px;border-left:4px solid #ffa500;}}
        .finding.high {{border-color:#ff0040;}}
        .finding.medium {{border-color:#ffa500;}}
        .finding.low {{border-color:#4a90d9;}}
        table {{width:100%;border-collapse:collapse;margin:10px 0;}}
        th, td {{padding:10px;text-align:left;border-bottom:1px solid #3d3d5a;}}
        th {{color:#00d4ff;}}
        .defense {{background:#0f3460;padding:15px;border-radius:8px;margin-top:20px;}}
        .defense h3 {{color:#00d4ff;}}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🔍 Binary Analysis Report</h1>
        <p>File: {os.path.basename(self.filepath)}</p>
        <p>Type: {self.info.get('file_type', 'Unknown')}</p>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="section">
        <h2>📊 Risk Assessment</h2>
        <div class="risk-score risk-{risk_level.lower()}">{self.risk_score}/100</div>
        <p style="text-align:center;">Risk Level: <strong>{risk_level}</strong></p>
        <p style="text-align:center;color:#888;">{len(self.findings)} security issues found</p>
    </div>
    
    <div class="section">
        <h2>📋 File Information</h2>
        <div>
            <div class="stat-box"><div class="value">{self.info.get('file_type', 'N/A')}</div><div class="label">Type</div></div>
            <div class="stat-box"><div class="value">{self.info.get('entry_point', 'N/A')}</div><div class="label">Entry Point</div></div>
            <div class="stat-box"><div class="value">{self.info.get('number_of_sections', 'N/A')}</div><div class="label">Sections</div></div>
        </div>
    </div>
    
    <div class="section">
        <h2>⚠️ Security Issues</h2>"""
        
        if not self.findings:
            html += '<p style="color:#00ff88;">✅ No security issues detected!</p>'
        else:
            for finding in self.findings:
                sev_class = finding['severity'].lower()
                html += f"""
        <div class="finding {sev_class}">
            <span style="font-weight:bold;">[{finding['severity']}]</span>
            <strong>{finding['type']}</strong>
            <p>{finding['description']}</p>
            <p style="color:#888;font-size:12px;">→ {finding['recommendation']}</p>
        </div>"""
        
        html += """
    </div>
    
    <div class="section">
        <h2>📦 Sections</h2>
        <table>
            <tr><th>Name</th><th>Size (bytes)</th><th>Address</th></tr>"""
        
        for section in self.info.get('sections', [])[:20]:
            html += f"""
            <tr>
                <td>{section.get('name', 'Unknown')}</td>
                <td>{section.get('size', section.get('virtual_size', 0))}</td>
                <td>{section.get('address', section.get('virtual_address', 'N/A'))}</td>
            </tr>"""
        
        html += """
        </table>
    </div>
    
    <div class="section">
        <h2>📥 Imports</h2>"""
        
        if self.info.get('imports'):
            if isinstance(self.info['imports'][0], dict):
                for imp in self.info['imports'][:10]:
                    html += f"""<p><strong>{imp['dll']}</strong></p><ul>"""
                    for func in imp['functions'][:10]:
                        html += f"<li>{func}</li>"
                    html += "</ul>"
            else:
                html += "<ul>"
                for imp in self.info['imports'][:20]:
                    html += f"<li>{imp}</li>"
                html += "</ul>"
        else:
            html += "<p style='color:#888;'>No imports detected</p>"
        
        html += """
    </div>
    
    <div class="section defense">
        <h3>🛡️ Defenses Against Binary Analysis</h3>
        <table>
            <tr><th>Technique</th><th>Description</th></tr>
            <tr><td>Obfuscation</td><td>Make analysis harder</td></tr>
            <tr><td>Packing</td><td>Compress/encrypt executable</td></tr>
            <tr><td>Anti-debugging</td><td>Detect debuggers</td></tr>
            <tr><td>Anti-disassembly</td><td>Confuse disassemblers</td></tr>
            <tr><td>Code Encryption</td><td>Encrypt sections</td></tr>
        </table>
    </div>
    
    <div style="text-align:center;color:#666;margin-top:30px;font-size:12px;">
        <p>Generated by Binary Analyzer | 100 Ethical Hacking Projects</p>
    </div>
</div>
</body>
</html>"""
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"{Colors.OKGREEN}[+] Report saved to {self.output_file}{Colors.ENDC}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="PE/ELF Binary Analyzer")
    parser.add_argument("--file", required=True, help="Binary file to analyze")
    parser.add_argument("--output", default="binary_report.html", help="HTML report file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    analyzer = BinaryAnalyzer(args.file, args.output, args.verbose)
    analyzer.run_analysis()

if __name__ == "__main__":
    main()