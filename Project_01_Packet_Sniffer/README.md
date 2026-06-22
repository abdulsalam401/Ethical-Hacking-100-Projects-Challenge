# 🛠️ Network Packet Sniffer & Protocol Analyzer

This project is part of the **[Ethical-Hacking-100-Projects-Challenge](https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge)** challenge. It is an educational utility designed to study cybersecurity concepts, network protocols, and system defenses.

---

## 📌 Project Overview
A low-level network packet sniffer that captures, decodes, and analyzes Ethernet frames and IP packets in real-time. It extracts crucial headers for TCP, UDP, and ICMP protocols, offering deep visibility into local network traffic.

### ⚙️ Specifications & Tech Stack
- **Category:** Ethical Hacking / Cyber Security Lab
- **Language:** Python / C (where applicable)
- **Tech Stack:** `Python 3`, `Scapy`, `Raw Sockets`, `struct`, `socket`
- **Prerequisites:** `scapy`, `colorama (optional for custom setups)`

---

## 🚀 Key Features
- Real-time packet capture using Scapy or native raw sockets as a fallback.
- Decodes layer 2 (Ethernet) and layer 3 (IP) headers.
- Parses transport layer protocols (TCP, UDP, and ICMP type/code fields).
- Colorized console output for easy reading of protocol structures.
- Graceful handling of Ctrl+C to stop sniffing and output summaries.

---

## 📖 Installation & Usage

### 1. Install Dependencies
Make sure you have Python 3 and the required libraries installed:
```bash
pip install -r requirements.txt
```
*(If a local `requirements.txt` is not present, install manually using `pip install scapy colorama (optional for custom setups)`)*

### 2. Execution Commands
Choose the command depending on your operating system:

**Windows Command Prompt / PowerShell:**
```cmd
python packetsniffer.py
```

**Linux / macOS Terminal:**
```bash
sudo python3 packetsniffer.py
```

*Note: Some projects require administrative privileges (root/sudo) to bind to raw sockets, monitor network interfaces, or intercept system APIs.*

---

## ⚠️ Legal & Ethical Disclaimer
> **IMPORTANT WARNING:** This tool is created strictly for educational, defensive, and authorized security auditing purposes. Ensure you have permission to sniff network traffic on the active interface. Running packet sniffers in unauthorized environments is a violation of privacy and security policies. The developer (**Abdul Salam**) assumes no liability for misuse, damage, or legal consequences resulting from the deployment of this tool.

---

## 👤 Developer Profile
- **Developer:** [Abdul Salam](https://salamcs.app)
- **GitHub:** [salam.cyber1](https://github.com/abdulsalam401)
- **LinkedIn:** [Abdul Salam](https://www.linkedin.com/in/abdul-salam-39467a274)
- **Portfolio:** [salamcs.app](https://salamcs.app)
