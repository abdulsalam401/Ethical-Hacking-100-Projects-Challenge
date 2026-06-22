# 🛠️ Android APK Static Security Scanner

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
A static analysis tool for Android applications (APKs). It scans manifest files and decompiled strings, analyzes permissions, checks security settings (like debuggable flags and backup configurations), and identifies potential vulnerabilities.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `zipfile`, `xml.etree.ElementTree`, `re`
- **Prerequisites:** `None (Uses standard libraries)`

---

## 🚀 Key Features
- Analyzes `AndroidManifest.xml` parameters: `allowBackup`, `usesCleartextTraffic`, and `debuggable` flags.
- Scans app permissions and flags high-risk requests (e.g., SMS access, background location).
- Identifies exported components (activities, services) that could be vulnerable to intent hijacking.
- Outputs audit summaries in formatted HTML reports.
- Uses YARA-style string scanning to flag dangerous API calls.

---

## 📖 Installation & Usage

### 1. Install Dependencies
Make sure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt
```
*(If a local `requirements.txt` is not present, install manually using `pip install None (Uses standard libraries)`)*

### 2. Execution Commands
Choose the command depending on your operating system:

**Windows Command Prompt / PowerShell:**
```cmd
python apk_scanner.py
```

**Linux / macOS Terminal:**
```bash
python3 apk_scanner.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. Decompiling and scanning application packages should only be done on apps you own or have permission to audit. Respect app licensing and intellectual property. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
