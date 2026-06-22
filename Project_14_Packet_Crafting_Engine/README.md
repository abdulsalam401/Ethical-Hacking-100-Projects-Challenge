# 🛠️ Raw Packet Assembler & Anomaly Analyzer

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
A network security tool that crafts custom TCP, UDP, and ICMP packets. It allows security auditors to inject custom payloads and flags, transmitting them to target systems and logging abnormal replies (like ICMP Destination Unreachable) to identify firewall rules.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `Scapy`
- **Prerequisites:** `scapy`

---

## 🚀 Key Features
- Custom packet crafting for TCP, UDP, and ICMP protocols.
- Adjustable parameters: source IP, destination IP, ports, flags, and payload contents.
- Response analyzer: captures replies and logs anomalies.
- Colorized output indicating transmission states.

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
python fuzzer.py
```

**Linux / macOS Terminal:**
```bash
sudo python3 fuzzer.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. Crafting and sending raw packets can be detected as network attacks. Ensure you audit only target addresses within your lab boundaries. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
