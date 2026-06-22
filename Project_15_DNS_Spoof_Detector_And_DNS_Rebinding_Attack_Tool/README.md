# 🛠️ DNS Spoof Detector & DNS Rebinding Lab

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
A dual-purpose DNS security auditing package. It includes: 1. A sniffer that checks local DNS responses against a trusted resolver (like Cloudflare) to detect poisoning. 2. A simulated DNS rebinding server demonstrating how attackers can bypass browser Same-Origin Policies.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `Scapy`, `dnslib`, `http.server`, `json`
- **Prerequisites:** `scapy`, `dnslib`

---

## 🚀 Key Features
- DNS Spoof Detector: sniffs DNS responses and cross-checks mappings with a trusted resolver.
- DNS Rebinding server: dynamically switches DNS responses between public and local IP addresses.
- Local HTTP Server: hosts a proof-of-concept page to illustrate browser-based rebinding exploits.
- Saves spoofing alerts to structured JSON logs.

---

## 📖 Installation & Usage

### 1. Install Dependencies
Make sure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt
```
*(If a local `requirements.txt` is not present, install manually using `pip install scapy dnslib`)*

### 2. Execution Commands
Choose the command depending on your operating system:

**Windows Command Prompt / PowerShell:**
```cmd
python dns_detector.py  (or) python dns_rebinder.py
```

**Linux / macOS Terminal:**
```bash
sudo python3 dns_detector.py  (or) sudo python3 dns_rebinder.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. DNS rebinding is a critical web vulnerability vector. Do not deploy rebinding scripts on public DNS servers; run them within local sandboxes. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
