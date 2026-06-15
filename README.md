<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&pause=1000&color=00FF00&center=true&vCenter=true&width=435&lines=Scope;KaguraV01d;Full+Reconnaissance+%26+Vulnerability;Ethical+Security+Tool" alt="Typing SVG" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0-brightgreen" alt="Version 2.0">
  <img src="https://img.shields.io/badge/language-Bash-blue" alt="Language">
  <img src="https://img.shields.io/badge/license-MIT-red" alt="License">
  <img src="https://img.shields.io/badge/tools-20%2B-orange" alt="Tools">
</p>

## Overview

**Scope** is a comprehensive, modular reconnaissance and vulnerability assessment framework designed for security professionals. It orchestrates 20+ security tools in a structured workflow, from subdomain discovery to detailed vulnerability reporting.

> **IMPORTANT**: This tool is for authorized testing only. Only use on targets you have explicit written permission to test.

## Features

- **Modular Architecture** — Run individual modules or full pipeline
- **Parallel Execution** — Job queue system with configurable concurrency  
- **7+ Passive Sources** — Subfinder, Assetfinder, crt.sh, OTX, HackerTarget, RapidDNS, Anubis
- **Smart Subdomain Permutation** — Alterx + dnsx for intelligent discovery
- **Comprehensive URL Collection** — GAU, Waybackurls, Katana (JS-aware crawling)
- **JavaScript Analysis** — Extract JS files and scan for 15+ secret patterns
- **Port Scanning** — Naabu top-1000 port scan
- **Technology Detection** — HTTPX with tech stack fingerprinting
- **Vulnerability Scanning** — Dedicated tools per category:
  - XSS → Dalfox + Nuclei
  - SQLi → SQLMap + Nuclei  
  - LFI/SSRF/SSTI → GF patterns + Nuclei
  - RCE/XXE/CVE → Nuclei templates
  - Misconfigurations → Nuclei (misconfig, exposure, default creds)
  - Subdomain Takeover → Subjack + Nuclei
  - Cloud/Bucket → Nuclei (AWS, GCP, Azure, Firebase)
- **Rich Reporting** — Summary statistics + detailed vulnerability findings
- **TDD-Ready** — Unit test suite (`TEST_MODE=1`)

## Required Tools

The script auto-installs Go tools but requires these dependencies:

### Go Tools (auto-installed)
| Tool | Purpose |
|------|---------|
| subfinder | Passive subdomain discovery |
| alterx | Subdomain permutation |
| dnsx | DNS resolution |
| httpx | HTTP probing |
| naabu | Port scanning |
| katana | Web crawling |
| nuclei | Vulnerability scanning |
| gau | URL collection |
| waybackurls | Archive URLs |
| assetfinder | Asset discovery |
| dalfox | XSS scanning |
| qsreplace | URL parameter handling |
| gf | Pattern matching |
| anew | Deduplication |

### External Dependencies
- **Go** (1.20+) — Required for tool installation
- **jq** — JSON parsing for API responses
- **curl** — HTTP requests
- **sqlmap** — SQL injection (optional but recommended)
- **ffuf** — Web fuzzing (optional)

### Installation (Linux)
```bash
# Clone and run
git clone https://github.com/Fairuz-Ardion/Scope_Recon_Tools
cd Scope_Recon_Tools
chmod +x scope.sh

# Basic usage
sudo ./scope.sh
```

### Example Report Output
<img width="395" height="441" alt="image" src="https://github.com/user-attachments/assets/aad2f56b-f151-4b9e-a859-1a063b4b6198" />

### Author
KaguraV01d
GitHub: @Fairuz-Ardion
