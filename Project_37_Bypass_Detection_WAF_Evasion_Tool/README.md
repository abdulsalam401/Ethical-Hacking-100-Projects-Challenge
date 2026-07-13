# Project 37 - WAF Evasion Tool

Project 37 is a small lab for studying web application firewall behavior in a controlled environment. It includes a local WAF simulator and a payload variant generator that tests different encodings and obfuscation tricks against a target URL you control.

This project is documented from the repository index in [../README.md](../README.md), and this page links back there so you can move between the top-level catalog and the project-specific notes.

## Files

- [waf_simulator.py](waf_simulator.py): Flask app that simulates a simple WAF-protected search endpoint.
- [waf_evader.py](waf_evader.py): CLI tool that generates payload variants and checks whether the target blocks them.

## What It Demonstrates

- Pattern-based blocking with regular expressions.
- Variant generation using URL encoding, double encoding, case changes, comment insertion, and whitespace tricks.
- A simple way to compare blocked responses against allowed responses in a local lab.
- Basic reporting of variants that appear to bypass the simulated WAF.

## Requirements

- Python 3.8 or newer.
- `Flask` for the simulator.
- `requests` for the evasion tester.
- `colorama` is optional, but it improves terminal output.

Install the dependencies with:

```bash
pip install flask requests colorama
```

## Run the Simulator

Start the local test site first:

```bash
python3 waf_simulator.py
```

Then open:

```text
http://127.0.0.1:5000
```

The search endpoint is:

```text
http://127.0.0.1:5000/search?q=test
```

## Run the Evader

Use a target you are authorized to test. A local example looks like this:

```bash
python3 waf_evader.py --payload "' OR '1'='1" --url "http://127.0.0.1:5000/search?q=test"
```

Optional flags:

- `--param` to override the query parameter name.
- `--output` to choose the report file name.
- `--verbose` for more detailed console output.

Example with a custom output file:

```bash
python3 waf_evader.py --payload "' OR '1'='1" --url "http://127.0.0.1:5000/search?q=test" --output bypasses.txt --verbose
```

## Output

- Successful variants are printed in the terminal.
- Results are saved to `bypasses.txt` by default.
- The simulator returns `403` for blocked requests and a normal search response for allowed ones.

## Ethical Use

This project is for defensive learning, lab validation, and authorized testing only. Do not point it at systems you do not own or have explicit permission to assess.

## Back To Repository Index

Return to the main catalog in [../README.md](../README.md).