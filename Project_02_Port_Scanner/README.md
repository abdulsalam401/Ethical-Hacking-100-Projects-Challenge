# 🛠️ TCP Connect & SYN Stealth Port Scanner

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
A dual-mode network port scanning tool. It implements a standard TCP Connect scanner (Method 1) and a Scapy-based TCP SYN Stealth scanner (Method 2, half-open scanning) to identify active services on target hosts while comparing speed and stealth metrics.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `Scapy`, `Socket Programming`, `colorama`
- **Prerequisites:** `scapy`, `colorama`

---

## 🚀 Key Features
- Method 1: TCP Connect scan using standard Python socket library (no root required).
- Method 2: SYN Stealth scan using Scapy to send half-open TCP requests (root required).
- Banner grabbing for open ports to identify underlying service versions.
- Custom port range selection and well-known port mapping.
- Comparison metrics highlighting the time and packet overhead differences between methods.

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
python portscanner.py
```

**Linux / macOS Terminal:**
```bash
sudo python3 portscanner.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. Scanning ports of machines you do not own or have written permission to audit is illegal. Always test using local sandbox machines (e.g., Metasploitable or localhost). The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
