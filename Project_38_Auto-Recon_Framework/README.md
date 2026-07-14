# Project 38: Auto-Recon Framework

Part of the **Ethical Hacking 100 Projects Challenge**, this project is an automated reconnaissance lab for educational and authorized security testing. It combines DNS lookups, subdomain discovery, WHOIS queries, port scanning, and basic service fingerprinting into a single CLI workflow, then writes the findings into an HTML report.

## Overview

Auto-Recon is designed to help you study the reconnaissance phase of a security assessment in a controlled way. Given a domain you are allowed to test, it attempts to gather:

1. DNS records such as `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, and `SOA`.
2. Common subdomains using a built-in wordlist.
3. WHOIS registration details when the optional dependency is available.
4. Open ports from a curated top-port list.
5. Basic web service and technology fingerprints on HTTP and HTTPS services.

## Features

- DNS record enumeration with `dnspython`.
- Threaded subdomain discovery.
- WHOIS lookup support through `python-whois`.
- Threaded TCP port scanning using `socket`.
- Optional HTTP and HTTPS service fingerprinting with `requests` and `BeautifulSoup`.
- HTML report generation with a readable summary of findings.
- Quick mode for a shorter scan that checks the top 20 ports.

## Files

- [auto_recon.py](auto_recon.py): Main reconnaissance CLI and report generator.
- [report.html](report.html): Sample HTML output created by the tool.

## Requirements

- Python 3.8 or newer.
- `dnspython`
- `requests`
- `python-whois`
- `beautifulsoup4`
- `colorama` is optional, but it improves console output.

Install the dependencies with:

```bash
pip install dnspython requests python-whois beautifulsoup4 colorama
```

## Usage

Run a full reconnaissance scan on a domain you own or are authorized to assess:

```bash
python3 auto_recon.py --domain example.com
```

Useful options:

- `--threads` to change the number of worker threads.
- `--rate-limit` to control request pacing.
- `--output` to rename the generated HTML report.
- `--quick` to scan only the top 20 ports.

Example with a custom report name and quick mode:

```bash
python3 auto_recon.py --domain example.com --quick --output recon_report.html
```

## Output

- Console output shows progress for DNS, WHOIS, subdomains, ports, and services.
- The HTML report summarizes discovered records, open ports, services, and technologies.
- By default, the report is written to `recon_report.html`.

## Ethical Use

This tool is for defensive learning, lab validation, and authorized testing only. Do not scan domains, hosts, or infrastructure you do not own or have explicit permission to assess.

## Back To Repository Index

Return to the main catalog in [../README.md](../README.md).