# 🛠️ Multi-Threaded Port Scanner & Banner Grabber

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
A fast port scanner. It uses thread pools to scan ports concurrently, resolves hostnames, checks for service banners, implements rate-limiting, and outputs scan results in JSON format.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `socket`, `json`, `ThreadPoolExecutor`, `colorama`
- **Prerequisites:** `colorama`

---

## 🚀 Key Features
- Concurrently scans ports using ThreadPoolExecutor.
- Banner grabbing: captures service version strings from open ports.
- Supports rate-limiting to minimize network congestion.
- Saves scan results in structured JSON files.
- Fallback checks to identify host status before starting scans.

---

## 📖 Installation & Usage

### 1. Install Dependencies
Make sure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt
```
*(If a local `requirements.txt` is not present, install manually using `pip install colorama`)*

### 2. Execution Commands
Choose the command depending on your operating system:

**Windows Command Prompt / PowerShell:**
```cmd
python port_scanner.py
```

**Linux / macOS Terminal:**
```bash
python3 port_scanner.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. Always check your target destination before scanning, as high-frequency port scanning can be detected as an intrusion attempt. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
