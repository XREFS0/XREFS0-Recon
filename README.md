<p align="center">
  <img src="assets/masa.png" alt="XREFS0-Recon">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0-ff4444?style=flat-square" alt="Version 2.0"/>
  <img src="https://img.shields.io/badge/Modules-38%2B-00d4ff?style=flat-square" alt="38+ Modules"/>
  <img src="https://img.shields.io/badge/License-MIT-00ff88?style=flat-square" alt="MIT License"/>
  <img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat-square&logo=python" alt="Python 3.8+"/>
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-5a7a9a?style=flat-square" alt="Cross-platform"/>
</p>

---

**XREFS0** is a unified domain reconnaissance engine that weaves **38+ modules** into a single command — from passive enumeration to active probing, from SSL analysis to CVE matching, from email harvesting to network graph visualization.

No API keys. No scattered tools. One command, complete picture.

---

## Quick Start

```bash
pip install -r requirements.txt

# Full reconnaissance — HTML + JSON auto-generated
python xrefs0.py example.com

# Stealth scan through SOCKS5
python xrefs0.py example.com --profile stealth --proxy socks5://127.0.0.1:9050

# Targeted scan (specific modules only)
python xrefs0.py example.com --only-modules whois subdomains dns ssl
```

---

## Architecture

XREFS0 operates in **6 parallel execution groups**, each running independent modules concurrently:

| Phase | Modules | Description |
|-------|---------|-------------|
| **A** | WHOIS, Subdomains, Mail, Dorks | Passive intelligence gathering |
| **B** | DNS, Reverse DNS, Real IP | Network resolution & CDN bypass |
| **C** | HTTP, SSL, Ports | Service probing & certificate analysis |
| **D** | Security, WAF, Takeover, Directories, Swagger, CI/CD, Docker | Application-layer scanning |
| **E** | JS Extract, Spider, Wayback, CommonCrawl, Emails, S3, Cloud, GitHub, CVE, CMS | Deep content & vulnerability mining |
| **F** | Favicon, Screenshots, Graph | Post-processing & visualization |

Each phase is orchestrated with `ThreadPoolExecutor`, and modules within a phase run simultaneously — reducing total scan time by **60%+** compared to sequential execution.

---

## Capabilities

| Domain | What XREFS0 Extracts |
|--------|----------------------|
| **WHOIS** | Registrar, creation/expiry, domain status, days until expiry |
| **Subdomains** | Passive enumeration from 8 public sources (CRT, AlienVault, HackerTarget, DNSDumpster, RapidDNS, SecurityTrails, ThreatMiner, Anubis) |
| **DNS** | A, AAAA, MX, NS, TXT, CNAME, SOA, PTR records + AXFR zone transfer check |
| **DNS Brute-force** | Wordlist-driven subdomain resolution |
| **Real IP** | CDN/Proxy bypass via 7 detection methods (MX, NS, SOA, subdomain resolution, etc.) |
| **HTTP Probe** | Status codes, titles, server headers, redirect chains, CDN detection |
| **Technology** | 40+ fingerprint patterns — frameworks, languages, web servers, analytics |
| **SSL/TLS** | Certificate validity, issuer, subject, SANs, fingerprint, days remaining, expiry status |
| **Port Scan** | 45 tier-1 TCP ports with banner grabbing |
| **Security Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and 10+ more |
| **Mail Security** | SPF presence, DKIM signing, DMARC policy |
| **WAF Detection** | 15+ WAF signatures — Cloudflare, AWS WAF, ModSecurity, F5, Akamai |
| **CVE Matching** | Technology-to-CVE mapping via NVD database |
| **CMS Detection** | 50+ CMS fingerprints — WordPress, Drupal, Joomla, Magento, Shopify |
| **Subdomain Takeover** | 30+ cloud service fingerprints |
| **Cloud Storage** | AWS S3, GCP buckets, Azure blob containers |
| **JS Extraction** | Endpoints, API routes, secrets from JavaScript files |
| **Link Spider** | Recursive crawling for all discovered links |
| **Wayback / CommonCrawl** | Historical URL mining from web archives |
| **Google Dorks** | 40+ targeted dork queries |
| **GitHub Recon** | Code search, repository discovery, credential scanning |
| **Directory Enum** | 1000+ path brute-force |
| **API Discovery** | OpenAPI, Swagger, GraphQL introspection |
| **CI/CD Discovery** | 70+ file signatures — Jenkins, GitLab CI, GitHub Actions, Terraform |
| **Docker Registry** | Exposed registry detection |
| **Favicon Hash** | mmh3, MD5, SHA256 hashing |
| **Screenshots** | Webpage capture via Playwright |
| **Graph Visualization** | Interactive D3.js force-directed network graph |
| **Vulnerability Scan** | SQLi reflection, XSS reflection, open redirect, `.env` exposure |

---

## Output Formats

| Flag | Format | Description |
|------|--------|-------------|
| `--html` | HTML | Dark-theme report with collapsible sections, all data in one file |
| `--json` | JSON | Complete structured data dump |
| `--yaml` | YAML | YAML-formatted export |
| `--csv` | CSV | Subdomain table export |
| `--xlsx` | XLSX | Multi-sheet Excel workbook |
| `--pdf` | PDF | Print-ready report (requires puppeteer) |
| `--markdown` | Markdown | Lightweight text summary |

When `--html` and `--json` are omitted, they default to `report.html` and `data.json` automatically.

---

## Scan Profiles

| Profile | Behavior |
|---------|----------|
| **`full`** (default) | All 38+ modules — maximum coverage, longest runtime |
| **`quick`** | Throttled subdomains/ports/spider — balance of speed and depth |
| **`stealth`** | Excludes brute-force, crawling, cloud, CI/CD, Docker — minimal footprint |

---

## Installation

```bash
git clone https://github.com/XREFS0/xrefs0.git
cd xrefs0
pip install -r requirements.txt
python xrefs0.py --version
```

---

## Examples

```bash
# Comprehensive scan with all outputs
xrefs0 example.com --html report.html --json data.json --pdf report.pdf --md report.md

# Batch scan (one report per domain)
xrefs0 --file domains.txt --html report_DOMAIN.html --json data_DOMAIN.json

# Deep dive — high concurrency, large scope
xrefs0 example.com --threads 100 --timeout 30 -m 500

# Rate-limited — polite scanning
xrefs0 example.com --rate-limit 10 --delay 0.5 -T 20

# CIDR network enumeration
xrefs0 example.com --cidr 192.168.1.0/24 10.0.0.0/8

# Resume interrupted scan
xrefs0 example.com --resume

# Custom wordlists
xrefs0 example.com --dirs-wordlist my_dirs.txt --subs-wordlist my_subs.txt
```

---

## Command-Line Reference

Full documentation with every flag, module, and example is available in [`COMMANDS.md`](COMMANDS.md).

```
Target:       domain | --file FILE | --cidr CIDRS
Output:       --html | --json | --yaml | --csv | --xlsx | --pdf | --markdown
Control:      -T NUM | -t SEC | -m NUM | -p MODE | -d SEC | -rl NUM
Network:      --proxy URL | --retry NUM | --resolvers IPs
Modes:        --silent | --quiet | --compact | --resume | --log FILE
Modules:      --only-modules [space separated names]
Disable:      --no-http | --no-port | --no-dirb | --no-vuln | ... (30+ flags)
```

---

## Project Structure

```
xrefs0/
├── xrefs0.py           # Entry point
├── config.yaml         # API keys configuration
├── requirements.txt    # Dependencies
├── README.md           # This document
├── COMMANDS.md         # Full command reference
├── LICENSE             # MIT License
├── SECURITY.md         # Security policy
├── CONTRIBUTING.md     # Contribution guidelines
├── CODE_OF_CONDUCT.md  # Community standards
├── wordlists/
│   ├── subdomains.txt  # 874 subdomain names
│   ├── dirs.txt        # 1011 directory paths
│   └── resolvers.txt   # 16 public DNS resolvers
└── modules/            # 38+ reconnaissance modules
    ├── output.py       # HTML/JSON/CSV/XLSX/PDF engine
    ├── dns_lookup.py   # Full DNS resolution
    ├── http_probe.py   # HTTP service probing
    ├── port_scan.py    # TCP port scanning
    ├── ssl_analyzer.py # SSL/TLS certificate analysis
    ├── cve_check.py    # CVE matching engine
    ├── takeover_check.py
    ├── graph_viz.py    # D3.js network graph
    ├── screenshot.py   # Webpage capture
    └── ...             # 30+ additional modules
```

---

## License

**MIT License** — See [`LICENSE`](LICENSE) for the full text.

You are free to use, modify, distribute, and sublicense this software for any purpose, including commercial applications, provided the original copyright notice is included.

---

<p align="center">
  <a href="https://t.me/XREFS0_CHANNEL"><img src="https://img.shields.io/badge/Telegram-Channel-00d4ff?style=flat-square&logo=telegram" alt="Telegram Channel"/></a>
  <a href="https://t.me/MrMasaOfficial"><img src="https://img.shields.io/badge/Telegram-Contact-ff4444?style=flat-square&logo=telegram" alt="Telegram Contact"/></a>
  <a href="https://www.youtube.com/@XREFS0"><img src="https://img.shields.io/badge/YouTube-XREFS0-ff0000?style=flat-square&logo=youtube" alt="YouTube"/></a>
  <a href="https://github.com/XREFS0"><img src="https://img.shields.io/badge/GitHub-XREFS0-6e5494?style=flat-square&logo=github" alt="GitHub"/></a>
  <a href="https://www.linkedin.com/in/mrmasaofficial"><img src="https://img.shields.io/badge/LinkedIn-mrmasaofficial-0077b5?style=flat-square&logo=linkedin" alt="LinkedIn"/></a>
  <a href="http://xrefs0.com/"><img src="https://img.shields.io/badge/Web-xrefs0.com-00ff88?style=flat-square&logo=google-chrome" alt="Website"/></a>
</p>

<p align="center">
  <sub>XREFS0 — Cyber Intelligence & Domain Reconnaissance &middot; Coded by MASA &middot; Protocol: Dark Recon</sub>
</p>
