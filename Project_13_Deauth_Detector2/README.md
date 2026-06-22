# 🛠️ 802.11 Wi-Fi Deauth Detector (Refined Version)

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
A refined version of the Wi-Fi Deauthentication detector. It tracks traffic volume, maps deauth codes, manages interface states, and alerts when packets exceed safe thresholds, suggesting mitigation actions.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `Scapy`, `time`
- **Prerequisites:** `scapy (Linux with monitor mode support is recommended)`

---

## 🚀 Key Features
- Threshold-based alert logic (e.g. alert if > 30 deauth frames are received within 5 seconds).
- Cleans old packet timestamps automatically to prevent memory bloat.
- Decodes Wi-Fi reason codes (e.g., Unspecified, Class 2/3 frame from nonassociated station).
- Mitigation suggestions on console (e.g., advising WPA3 or Management Frame Protection).

---

## 📖 Installation & Usage

### 1. Install Dependencies
Make sure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt
```
*(If a local `requirements.txt` is not present, install manually using `pip install scapy (Linux with monitor mode support is recommended)`)*

### 2. Execution Commands
Choose the command depending on your operating system:

**Windows Command Prompt / PowerShell:**
```cmd
N/A (Requires Linux with Monitor Mode support)
```

**Linux / macOS Terminal:**
```bash
sudo python3 deauth_detector2.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. Use this tool to monitor your wireless infrastructure for intrusion attempts or deauth flooding. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
