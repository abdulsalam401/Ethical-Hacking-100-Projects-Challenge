# 🔍 Project 35: PE/ELF Binary Analysis & Mitigation Auditor

Part of the **Ethical Hacking 100 Projects Challenge**. This project is a cross-platform, cross-architecture static analysis utility designed to parse Portable Executable (PE) and Executable and Linkable Format (ELF) files. It verifies compiler-level security configurations and exploit mitigations, calculates section entropy to flag potential packing or encryption, and generates detailed HTML forensics reports.

---

## 📖 Overview

When auditing systems or analyzing malware, evaluating a binary's structural layout and compiler-enforced defenses is crucial. This tool automates static analysis by:
1. **Identifying Executables**: Auto-detects file type (Windows PE or Linux ELF) using magic byte signatures (`MZ` or `\x7fELF`).
2. **Auditing Exploit Mitigations**: Inspects header directories and segment flags to verify modern system protections.
3. **Analyzing Obfuscation & Packing**: Calculates Shannon Entropy for program sections; values $> 7.0$ suggest compression, encryption, or custom packer signatures.
4. **Extracting Imports & Exports**: Maps external API dependencies and exported entry points to trace potential execution behavior.

---

## 🛠️ Features

- **Exploit Mitigation Matrix**:
  - **Windows PE**: Audits ASLR (`DYNAMIC_BASE`), DEP/NX (`NX_COMPAT`), Stack Cookies (`/GS`), SafeSEH, Control Flow Guard (`CFG`), and Digital Code Signing.
  - **Linux ELF**: Audits RELRO (Relocation Read-Only), NX (non-executable stack flag), PIE (Position Independent Executable), and Stack Canary (`__stack_chk_fail`).
- **Obfuscation Detection**: Analyzes raw binary chunks to compute entropy rating (0 to 8).
- **Import/Export Directory Parsing**: Lists DLL/SO linkages and API function references.
- **Dynamic HTML Report Dashboard**: Compiles risk levels (Critical, High, Medium, Low), detailed vulnerability descriptions, section details, and mitigation alerts into a premium visual HTML report.
- **Colorized CLI Output**: Outputs audit warnings directly to stdout for fast terminal assessments.

---

## 📂 File Structure

- [binary_analyzer.py](file:///d:/100%20Projects%20Challenge/Project_35_PE_ELF_Analysis_Tool/binary_analyzer.py): Base structural scanner with standard PE/ELF parsing, mitigation checks, and basic HTML tables.
- [binary_analyzer2.py](file:///d:/100%20Projects%20Challenge/Project_35_PE_ELF_Analysis_Tool/binary_analyzer2.py): Enhanced version featuring detailed check validations (SafeSEH, CFG, Code Signing), advanced section listing, colorized CLI, and a dark-theme responsive HTML dashboard.

---

## ⚙️ Setup & Installation

The tool requires python 3 and external parsing libraries.

Install the dependencies:
```bash
pip install pefile pyelftools colorama
```

---

## 🚀 Usage

### 1. Basic PE Audit (Base Version)
```bash
python binary_analyzer.py --file path/to/target.exe --output pe_audit_report.html
```

### 2. Enhanced Cross-Platform Audit
Run the enhanced analyzer to audit any PE or ELF binary and generate the interactive dark-themed report:
```bash
python binary_analyzer2.py --file path/to/target.elf --output elf_audit_report.html
```

### Command-Line Arguments:
* `--file` (Required): Path to the target executable to audit.
* `--output` (Optional): Target path for the output HTML report (default: `binary_report.html`).
* `--verbose` / `-v` (Optional): Enable verbose standard output logs during structural parsing.

---

## 🛡️ Exploit Mitigation & Compiler Flags

Ensure your production binaries are protected by configuring compilation environments with the following hardening flags:

### For Microsoft Visual C++ (MSVC / Windows)
* **Enable ASLR**: `/DYNAMICBASE` (Linker)
* **Enable DEP**: `/NXCOMPAT` (Linker)
* **Enable Stack Cookies**: `/GS` (Compiler)
* **Enable Control Flow Guard**: `/GUARD:CF` (Compiler & Linker)
* **Enable SafeSEH**: `/SAFESEH` (Linker, x86 only)

### For GCC / Clang (Linux)
* **Enable Full RELRO**: `-Wl,-z,relro,-z,now` (Linker)
* **Enable NX Stack**: `-z noexecstack` (Linker)
* **Enable PIE**: `-fPIE -pie` (Compiler & Linker)
* **Enable Stack Canary**: `-fstack-protector-strong` or `-fstack-protector-all` (Compiler)

---

## ⚠️ Disclaimer
This tool is designed for educational research, penetration testing verification, and authorized defensive auditing. Analyzing untrusted binaries should be conducted in an isolated sandbox or analysis virtual machine.
