# 🛠️ System Process Monitor & Anti-Debugging Audit Tool

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
A local system security auditor. It monitors running processes, flags masqueraded executables, checks for suspicious behaviors, and tests for anti-debugging tricks (like PEB check flags on Windows and self-ptracing on Linux).

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `psutil`, `ctypes`, `sys`
- **Prerequisites:** `psutil`, `colorama`

---

## 🚀 Key Features
- Real-time process listing with path checks to identify masquerading.
- Suspicious process flagging: identifies processes running from temporary folders.
- Anti-debugging check: detects if the current process is being analyzed or debugged.
- Cross-platform compatibility: supports Windows and Linux APIs.
- Saves process telemetry history.

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
python monitor.py
```

**Linux / macOS Terminal:**
```bash
sudo python3 monitor.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. This tool is defensive, designed to help you analyze running system processes and identify debugging indicators. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
