# 🛠️ ARP Spoofing & Cache Poisoning Detector

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
A local area network security monitor that detects ARP spoofing and Man-in-the-Middle (MitM) attacks. By sniffing ARP packets, it maintains a dynamic IP-to-MAC address mapping table and flags duplicate mappings or sudden address modifications.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `Scapy`, `Threading`, `signal`
- **Prerequisites:** `scapy`

---

## 🚀 Key Features
- Passive ARP packet sniffing to analyze ARP requests and replies.
- Dynamic ARP table state tracking to identify conflicts.
- Instant colorized security alerts when a MAC address conflict or duplicate IP-to-MAC mapping is observed.
- Maintains statistical counters of ARP frames to detect anomaly spikes.
- Graceful shutdown displaying the final observed state of the network ARP table.

---

## 📖 Installation & Usage

### 1. Install Dependencies
Make sure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt
```
*(If a local `requirements.txt` is not present, install manually using `pip install scapy`)*

### 2. Execution Commands
Choose the command depending on your operating system:

**Windows Command Prompt / PowerShell:**
```cmd
python arpspoof_detector.py
```

**Linux / macOS Terminal:**
```bash
sudo python3 arpspoof_detector.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. This tool is defensive and should be run on your local network to monitor for security anomalies. Ensure you have network administration clearance before running broad sniffers. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
