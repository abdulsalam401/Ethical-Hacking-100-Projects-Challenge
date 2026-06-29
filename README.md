<p align="center">
  <img src="https://github.com/user-attachments/assets/7475d562-42cd-48db-b63b-f82bc1bc3c85"
       alt="Ethical Hacking 100 Projects Challenge Banner"
       width="100%"
       style="max-width: 260px; height: auto; display: block; margin: 0 auto;" />
</p>

# 🛡️ Ethical Hacking 100 Projects Challenge

<p align="center">
  <a href="https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge">
    <img src="https://img.shields.io/github/stars/abdulsalam401/Ethical-Hacking-100-Projects-Challenge?style=for-the-badge&color=00d4ff&logo=github" alt="GitHub stars" />
  </a>
  <a href="https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge/forks">
    <img src="https://img.shields.io/github/forks/abdulsalam401/Ethical-Hacking-100-Projects-Challenge?style=for-the-badge&color=00d4ff&logo=github" alt="GitHub forks" />
  </a>
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python Version" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="License" />
  <img src="https://img.shields.io/badge/platform-windows%20%7C%20linux-lightgrey?style=for-the-badge" alt="Platform Support" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/progress-39%20%2F%20100%20projects-00d4ff?style=for-the-badge" alt="Progress" />
</p>

<p align="center">
  <code>███████████████░░░░░░░░░░░░░░░░░░░░░░░░░░ 39%</code>
</p>

---

## 📖 Welcome

Welcome to the **Ethical Hacking 100 Projects Challenge** repository! This is a curated collection of security research projects, network utility scripts, vulnerability scanners, and proof-of-concept tools. The project suite focuses on cybersecurity engineering, penetration testing, host/network analysis, and cryptographic simulation.

---

## 👤 Developer & Maintainer

<table align="center">
  <tr>
    <td align="center">
      <a href="https://salamcs.app">
        <img src="https://img.shields.io/badge/salamcs.app-00d4ff?style=for-the-badge&logo=google-chrome&logoColor=white" alt="Portfolio" />
      </a>
    </td>
    <td align="center">
      <a href="https://github.com/abdulsalam401">
        <img src="https://img.shields.io/badge/github-@abdulsalam401-181717?style=for-the-badge&logo=github&logoColor=white" alt="GitHub" />
      </a>
    </td>
    <td align="center">
      <a href="https://www.linkedin.com/in/abdul-salam-39467a274">
        <img src="https://img.shields.io/badge/linkedin-Abdul%20Salam-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn" />
      </a>
    </td>
  </tr>
</table>

---

## ⚠️ Ethical & Legal Disclaimer

> [!IMPORTANT]
> **LEGAL NOTICE & USE CONDITIONS**
> 
> The code, tools, and materials in this repository are created solely for **educational purposes, defensive research, and authorized security auditing**.
>
> Running scans, interception tools, or exploitation scripts against targets without **explicit, written authorization** is illegal and punishable by law. The developer (**Abdul Salam**) assumes no responsibility or liability for how these scripts are used, any system damage caused, or legal actions resulting from misuse of this code. Always practice safe, legal, and ethical hacking.

---

## 📂 Project Catalog by Security Domain

To make browsing these **39 projects** simple, they have been classified into four cybersecurity categories. Click on a category header to expand the projects index.

### 🌐 Category 1: Network Auditing & Packet Sniffing
<details>
<summary><b>Expand Network Security Projects (11 Projects)</b></summary>
<br>

| # | Project Name | Description | Key Tech Stack | Link |
|---|---|---|---|---|
| 01 | **Network Packet Sniffer** | Low-level Ethernet frame and IP packet real-time decoder. | `Python 3`, `Scapy`, `Raw Sockets` | [View Project](./Project_01_Packet_Sniffer) |
| 02 | **TCP Connect & SYN Stealth Scanner** | Dual-mode stealth network port scanning utility. | `Python 3`, `Scapy`, `Socket` | [View Project](./Project_02_Port_Scanner) |
| 03 | **ARP Spoofing & Poisoning Detector** | Monitor and flag ARP spoofing/MitM attacks. | `Python 3`, `Scapy`, `Threading` | [View Project](./Project_03_arpspoof%20detector) |
| 13 | **Subnet Scanner & OS Fingerprinter** | Parallelized host sweep scanning and service mapping. | `Python 3`, `Scapy`, `ThreadPool` | [View Project](./Project_12_Network_Scanner) |
| 14 | **802.11 Wi-Fi Deauth Attack Detector** | Wireless sniffer monitoring 802.11 deauth floods. | `Python 3`, `Scapy` | [View Project](./Project_13_Deauth_Detector) |
| 15 | **802.11 Wi-Fi Deauth Detector (v2)** | Refined version of the Wi-Fi deauth monitoring engine. | `Python 3`, `Scapy`, `time` | [View Project](./Project_13_Deauth_Detector2) |
| 16 | **Raw Packet Crafting Engine** | Low-level custom TCP, UDP, and ICMP frame constructor. | `Python 3`, `Scapy` | [View Project](./Project_14_Packet_Crafting_Engine) |
| 17 | **Interactive Packet Fuzzer** | Interactive command-line packet assembler and injection CLI. | `Python 3`, `Scapy`, `colorama` | [View Project](./Project_14_Packet_Crafting_Engine2) |
| 18 | **DNS Spoof & Rebinding Detector** | Dynamic traffic auditor mapping name resolver anomalies. | `Python 3`, `Scapy`, `dnslib` | [View Project](./Project_15_DNS_Spoof_Detector_And_DNS_Rebinding_Attack_Tool) |
| 29 | **Multi-Threaded Banner Grabber** | Rapid TCP port scanner extracting target service banners. | `Python 3`, `socket`, `json` | [View Project](./Project_26_Multi-Threaded_Port_Scanner) |
| 37 | **IoT UPnP & SSDP Security Auditor** | Multicast device discovery, XML parsing, and vulnerability checker. | `Python 3`, `requests` | [View Project](./Project_34_IoT_Scanner) |

</details>

### 🛡️ Category 2: System Forensics, Auditing & Binary Exploitation
<details>
<summary><b>Expand Forensics & Binary Auditing Projects (8 Projects)</b></summary>
<br>

| # | Project Name | Description | Key Tech Stack | Link |
|---|---|---|---|---|
| 19 | **Process Monitor & Anti-Debugging Audit** | Local process execution monitoring and anti-debugging checker. | `Python 3`, `psutil`, `ctypes` | [View Project](./Project_16_Process_Monitor_And_Anti-Debugging_Detector) |
| 21 | **PBKDF2-LSB Steganography Tool** | Securely embed and retrieve secret text in PNG files. | `Python 3`, `Pillow`, `cryptography` | [View Project](./Project_18_Steganography_Tool) |
| 22 | **Active Memory Forensics Analyzer** | Inspects RAM allocation maps to flag specific indicator strings. | `Python 3`, `psutil`, `colorama` | [View Project](./Project_19_Memory_Forensics_Analyzer) |
| 23 | **Binary Exploitation Lab (Buffer Overflow)** | C exploits, fuzzers, and ret2win lab architectures. | `C`, `Python 3`, `GCC` | [View Project](./Project_20_Binary_Exploitation—Simple_Buffer_Overflow) |
| 24 | **API Hooking & Module Integrity Detector** | Process memory integrity auditor that catches hooked APIs. | `Python 3`, `ctypes`, `psutil` | [View Project](./Project_21_API_Hooking_Detecter) |
| 25 | **SIEM Log Analyzer & Alert Engine** | Centralized audit log parser checking correlation rules. | `Python 3`, `json`, `colorama` | [View Project](./Project_22_Log_Analysis_And_SIEM_Simulator) |
| 30 | **Real-Time File Integrity Monitor (FIM)** | Folder monitoring tool tracking changes using cryptographic hashing. | `Python 3`, `hashlib`, `json` | [View Project](./Project_27_File_Integrity_Monitor) |
| 38 | **PE/ELF Binary Mitigation Auditor** | Structural static analyzer auditing compiler exploit mitigations. | `Python 3`, `pefile`, `pyelftools` | [View Project](./Project_35_PE_ELF_Analysis_Tool) |

</details>

### ☁️ Category 3: Web Application & Cloud Security
<details>
<summary><b>Expand Web & Cloud Projects (8 Projects)</b></summary>
<br>

| # | Project Name | Description | Key Tech Stack | Link |
|---|---|---|---|---|
| 06 | **Asynchronous Web Directory Crawler** | Multithreaded site map and hidden path discovery tool. | `Python 3`, `requests`, `ThreadPool` | [View Project](./Project_06_Web_Crawler) |
| 09 | **Blind SQL Injection Exploiter** | Web vulnerability scanner extracting databases via blind SQLi. | `Python 3`, `requests`, `SQLite3` | [View Project](./Project_09_SQL_Scanner) |
| 26 | **Android APK Static Vulnerability Scanner** | Unpacks APK files to flag insecure permissions and API imports. | `Python 3`, `zipfile`, `ElementTree` | [View Project](./Project_23_Android_App_Security_Scanner) |
| 27 | **Reverse Proxy WAF (Web App Firewall)** | Interactive proxy checking traffic for injection signatures. | `Python 3`, `http.server`, `urllib` | [View Project](./Project_24_Web_Application_Firewall) |
| 28 | **Web Vulnerability Mapper & Crawler** | Crawls forms and tests them for reflective XSS and basic issues. | `Python 3`, `requests`, `BeautifulSoup4` | [View Project](./Project_25_Vulnerability_Scanner_Web_Application) |
| 33 | **Tor Threat Intelligence Scraper** | Onion web query scraper routing traffic via local Tor proxy. | `Python 3`, `requests`, `Tor SOCKS5` | [View Project](./Project_30_Dark_Web_Scraper) |
| 35 | **AWS Cloud S3 Security Auditor** | Evaluates bucket configuration policies for public exposure risks. | `Python 3`, `boto3` | [View Project](./Project_32_Cloud_Security_Scanner) |
| 39 | **SQL Injection Exploitation Tool** | Multi-technique SQLi detection and data extraction framework. | `Python 3`, `requests`, `BeautifulSoup4` | [View Project](./Project_36_SQL_Injection_Exploitation_Tool) |

</details>

### 🧪 Category 4: Cryptography, Credentials & Malware Simulation
<details>
<summary><b>Expand Cryptography & Malware Sim Projects (12 Projects)</b></summary>
<br>

| # | Project Name | Description | Key Tech Stack | Link |
|---|---|---|---|---|
| 04 | **Stealth Keylogger with XOR Encryption** | Keyboard logging simulation utilizing raw win32 hooks. | `Python 3`, `pynput`, `ctypes` | [View Project](./Project_04_Keylogger) |
| 05 | **AES Command & Control Reverse Shell** | Encrypted interactive reverse terminal with GUI C2 dashboard. | `Python 3`, `pycryptodome`, `Socket` | [View Project](./Project_05_Revers_Shell) |
| 07 | **FTP Credential Brute-Forcer** | High-speed credential spray framework with request jitter. | `Python 3`, `ftplib`, `random` | [View Project](./Project_07_FTP_Cracker) |
| 08 | **SSH Credential Strength Auditor** | Paramiko-based SSH dictionary auditor using pooled transports. | `Python 3`, `Paramiko`, `Socket` | [View Project](./Project_08_SSH_Cracker) |
| 10 | **Telemetry Exfiltration Keylogger** | Telemetry capture tool exfiltrating clipboard details via SMTP. | `Python 3`, `pynput`, `smtplib` | [View Project](./Project_10_Keylogger_with_Email_Exfiltration) |
| 11 | **Ransomware Encryption Simulator** | Basic directory locking demonstration using symmetric keys. | `Python 3`, `cryptography` | [View Project](./Project_11_Ransomeware_Simulator) |
| 12 | **Ransomware Simulator with Safety Guards** | Advanced folder lock simulator with directory range constraints. | `Python 3`, `cryptography`, `json` | [View Project](./Project_11_Ransomeware_Simulator_2) |
| 20 | **SSL Interactive TTY Reverse Shell** | SSL-wrapped full command-and-control connection tool. | `Python 3`, `ssl`, `socket` | [View Project](./Project_17_Reverse_Shell_with_full_Interactive_TTY_And_File_Transfer) |
| 31 | **RAT Remote C2 Controller** | Command-and-control simulation platform with central web UI. | `Python 3`, `Flask`, `ssl` | [View Project](./Project_28_RAT) |
| 32 | **Web3 Smart Contract Auditor** | Static analysis scanner profiling Solidity source for flaws. | `Python 3`, `web3`, `re` | [View Project](./Project_29_Blockchain_Explorer_And_Smart_Contract%20Analyzer) |
| 34 | **Crypter & File Packer Utility** | Compresses and encrypts execution scripts inside safe wrappers. | `Python 3`, `cryptography`, `base64` | [View Project](./Project_31_Antivirus_Evasion—File_Packer) |
| 36 | **Password Cracker & Hash Matcher** | Dictionary matching engine supporting brute force mutations. | `Python 3`, `bcrypt` | [View Project](./Project_33_Password_Cracker) |

</details>

---

## ⚙️ Repository Setup & Usage

### 1. Clone the Repository
```bash
git clone https://github.com/abdulsalam401/Ethical-Hacking-100-Projects-Challenge.git
cd Ethical-Hacking-100-Projects-Challenge
```

### 2. Configure a Virtual Environment
It is highly recommended to isolate these projects in a Python virtual environment:
```bash
# Create a virtual environment
python -m venv venv

# Activate on Windows (CMD):
.\venv\Scripts\activate

# Activate on Linux / macOS:
source venv/bin/activate
```

### 3. Install Requirements
Ensure you have the required external libraries installed:
```bash
pip install scapy cryptography requests paramiko dnslib web3 psutil colorama pyperclip beautifulsoup4 flask pycryptodome pillow pefile pyelftools
```

---

## 📄 License

This repository is licensed under the [MIT License](LICENSE) - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <i>Developed with 💻 and 🛡️ by <a href="https://salamcs.app">Abdul Salam</a>.</i>
</p>
