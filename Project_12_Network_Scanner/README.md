# 🛠️ Network Scanner with ARP Sweeping & OS Fingerprinting

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
A comprehensive local network auditing tool. It scans local subnets using ARP requests, performs active TCP SYN port scanning on discovered hosts, and attempts OS Fingerprinting by evaluating TTL (Time to Live) and TCP Window sizes.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `Scapy`, `ThreadPoolExecutor`, `colorama`
- **Prerequisites:** `scapy`, `colorama`

---

## 🚀 Key Features
- Local host discovery via ARP Broadcast frames.
- Active TCP SYN scanning using ThreadPoolExecutor for fast checks.
- OS Fingerprinting: guesses target operating systems using TTL heuristics and window configurations.
- Traceroute: maps network path hops using incrementing TTL packets.
- Saves discoveries in structured JSON outputs for report compilation.

---

## 📖 Installation & Usage

### 1. Install Dependencies
Make sure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt
```
*(If a local `requirements.txt` is not present, install manually using `pip install scapy colorama`)*

### 2. Execution Commands
Choose the command depending on your operating system:

**Windows Command Prompt / PowerShell:**
```cmd
python scanner.py
```

**Linux / macOS Terminal:**
```bash
sudo python3 scanner.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. Do not scan large networks without prior clearance, as active scanning can trigger security alerts or slow down network segments. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
