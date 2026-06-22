# 🛠️ Live System Memory Forensics & Process Scan Tool

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
A forensic tool that scans active system memory. It lists process trees, compares active executables against a whitelist of legitimate processes, and flags signatures of known malware, remote access tools, or memory-dumping utilities (like Mimikatz).

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `psutil`, `colorama`, `json`, `re`
- **Prerequisites:** `psutil`, `colorama`

---

## 🚀 Key Features
- Live process scanning and parent-child tree mapping.
- Masquerading checks: compares running image paths with expected system paths.
- Signature detection: searches process parameters for malware indicators.
- Colorized CLI reports and structured JSON exports.

---

## 📖 Installation & Usage

### 1. Install Dependencies
Make sure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt
```
*(If a local `requirements.txt` is not present, install manually using `pip install psutil colorama`)*

### 2. Execution Commands
Choose the command depending on your operating system:

**Windows Command Prompt / PowerShell:**
```cmd
python memory_analyzer.py
```

**Linux / macOS Terminal:**
```bash
sudo python3 memory_analyzer.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. This tool is defensive, designed to help security analysts identify malicious processes and verify memory integrity. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
