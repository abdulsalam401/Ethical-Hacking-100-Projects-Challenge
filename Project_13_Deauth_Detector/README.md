# 🛠️ 802.11 Wi-Fi Deauthentication Attack Detector

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
A wireless security monitoring tool that sniffs 802.11 frames to detect Wi-Fi Deauthentication attacks (which force clients offline). It automates monitor-mode interfaces using standard tools like `airmon-ng` and flags suspicious spikes in deauth packets.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `Scapy`, `Monitor Mode Interface tools`
- **Prerequisites:** `scapy (Only compatible on platforms supporting Wi-Fi monitor mode, e.g. Linux)`

---

## 🚀 Key Features
- Automated setup and teardown of monitor-mode interfaces (via `airmon-ng` or `iw`).
- Sniffs 802.11 wireless frames, specifically looking for Deauthentication frames (subtype 12).
- Maps deauth reason codes to human-readable explanations.
- Alerts on rate thresholds to prevent false positives from standard disconnects.

---

## 📖 Installation & Usage

### 1. Install Dependencies
Make sure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt
```
*(If a local `requirements.txt` is not present, install manually using `pip install scapy (Only compatible on platforms supporting Wi-Fi monitor mode, e.g. Linux)`)*

### 2. Execution Commands
Choose the command depending on your operating system:

**Windows Command Prompt / PowerShell:**
```cmd
N/A (Requires Linux with Monitor Mode support)
```

**Linux / macOS Terminal:**
```bash
sudo python3 deauth_detector.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. Sniffing wireless packets requires your card to be in monitor mode. Ensure you own the wireless network you are auditing. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
