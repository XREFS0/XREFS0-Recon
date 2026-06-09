<p align="center">
  <img src="https://img.shields.io/badge/XREFS0-v2.0-ff4444?style=for-the-badge&labelColor=0a0e1a" alt="XREFS0 v2.0"/>
  <img src="https://img.shields.io/badge/Command-Reference-00d4ff?style=for-the-badge&labelColor=0a0e1a" alt="Command Reference"/>
</p>

<h1 align="center">XREFS0 — Command Reference</h1>
<p align="center"><b>Cyber Intelligence & Domain Reconnaissance Platform</b></p>
<p align="center"><i>Coded by <a href="https://github.com/XREFS0">MASA</a></i></p>

---

## Table of Contents

- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Command-Line Options](#command-line-options)
  - [Target Specification](#target-specification)
  - [Output Formats](#output-formats)
  - [Performance & Control](#performance--control)
  - [Operational Modes](#operational-modes)
  - [Module Disable Flags](#module-disable-flags)
- [Scan Profiles](#scan-profiles)
- [Examples](#examples)
  - [Full Reconnaissance](#full-reconnaissance)
  - [Stealth Mode](#stealth-mode)
  - [Quick Scan](#quick-scan)
  - [Targeted Modules](#targeted-modules)
  - [Rate-Limited Scan](#rate-limited-scan)
  - [Custom Wordlists](#custom-wordlists)
  - [Resume Scan](#resume-scan)
  - [Deep Scan](#deep-scan)
  - [Batch Processing](#batch-processing)
  - [CIDR Enumeration](#cidr-enumeration)
- [Module Catalog](#module-catalog)
- [File Structure](#file-structure)
- [Quick Reference](#quick-reference)
- [Connect](#connect)

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Basic Usage

```bash
# Minimal scan (all defaults)
xrefs0 example.com

# Full export suite (HTML + JSON + PDF + Markdown)
xrefs0 example.com --html report.html --json data.json --pdf report.pdf --md report.md

# Silent operation (no animations)
xrefs0 example.com --silent

# Automatic defaults (HTML + JSON)
xrefs0 example.com
# → Generates: report.html, data.json automatically
```

---

## Command-Line Options

### Target Specification

| Argument | Description |
|----------|-------------|
| `domain` | Target domain or URL to scan (required unless `--file` used) |
| `-f, --file FILE` | File containing domains to scan (one per line) |
| `--cidr CIDRS` | CIDR ranges for PTR/network enumeration (e.g. `192.168.1.0/24`) |

### Output Formats

> **Note:** When `--html` and `--json` are not specified, they default to `report.html` and `data.json` automatically.

| Flag | Description |
|------|-------------|
| `--html FILE` | Export comprehensive HTML report with collapsible sections |
| `--json FILE` | Export raw JSON data |
| `-y, --yaml FILE` | Export YAML data |
| `--csv FILE` | Export CSV subdomain data |
| `--xlsx FILE` | Export Excel spreadsheet (multi-sheet) |
| `--pdf FILE` | Export PDF report (requires puppeteer) |
| `-md, --markdown FILE` | Export Markdown report |

### Performance & Control

| Short | Full | Default | Description |
|-------|------|---------|-------------|
| `-T` | `--threads NUM` | `50` | Thread count for concurrent operations |
| `-t` | `--timeout SEC` | `10` | Request timeout in seconds |
| `-m` | `--max-subdomains NUM` | `0` (all) | Maximum subdomains to process |
| `-p` | `--profile MODE` | `full` | Scan profile: `full`, `quick`, `stealth` |
| `-d` | `--delay SEC` | `0` | Delay between requests (seconds) |
| `-rl` | `--rate-limit NUM` | `0` | Max requests per second |
| | `--proxy URL` | — | Proxy URL (e.g. `socks5://127.0.0.1:9050`) |
| | `--retry NUM` | `2` | Retry attempts on failure |
| | `--resolvers IPs` | System DNS + fallbacks | Custom DNS resolver IPs |
| | `--resume` | — | Resume last scan from history database |

### Operational Modes

| Short | Full | Description |
|-------|------|-------------|
| `-s` | `--silent` | Suppress animations and spinners |
| `-q` | `--quiet` | Minimal console output |
| | `--compact` | Compressed terminal output (single-line modules) |
| `-h` | `--help` | Display help and exit |
| `-v` | `--version` | Display version information and exit |
| `-c` | `--config FILE` | API keys configuration file (`config.yaml`) |
| `-l` | `--log FILE` | Write scan log to file |
| | `--only-modules MODULES` | Execute only specified modules (space-separated) |
| | `--dirs-wordlist FILE` | Custom directory brute-force wordlist |
| | `--subs-wordlist FILE` | Custom subdomain brute-force wordlist |
| | `--no-history` | Skip saving scan to history database |

### Module Disable Flags

| Flag | Description |
|------|-------------|
| `--no-http` | Skip HTTP probing |
| `--no-port` | Skip port scanning |
| `--no-dirb` | Skip directory enumeration |
| `--no-screenshot` | Skip screenshot capture |
| `--no-graph` | Skip D3.js graph generation |
| `--no-dns-brute` | Skip DNS brute-force |
| `--no-js-extract` | Skip JavaScript extraction |
| `--no-spider` | Skip link spider |
| `--no-waf` | Skip WAF detection |
| `--no-cloud` | Skip cloud storage scan |
| `--no-swagger` | Skip API documentation discovery |
| `--no-cicd` | Skip CI/CD configuration discovery |
| `--no-cms` | Skip CMS detection |
| `--no-docker` | Skip Docker registry scan |
| `--no-reverse-dns` | Skip reverse DNS lookup |
| `--no-wayback` | Skip Wayback Machine scraping |
| `--no-commoncrawl` | Skip CommonCrawl scraping |
| `--no-dorks` | Skip Google dork generation |
| `--no-github` | Skip GitHub reconnaissance |
| `--no-cve` | Skip CVE matching |
| `--no-whois` | Skip WHOIS lookup |
| `--no-subdomains` | Skip subdomain enumeration |
| `--no-dns` | Skip DNS resolution |
| `--no-real-ip` | Skip real IP detection |
| `--no-ssl` | Skip SSL analysis |
| `--no-mail` | Skip mail security check |
| `--no-security` | Skip security headers scan |
| `--no-asn` | Skip ASN/Geo lookup |
| `--no-takeover` | Skip takeover check |
| `--no-s3` | Skip S3 bucket scan |
| `--no-emails` | Skip email harvesting |
| `--no-favicon` | Skip favicon hash calculation |
| `--no-vuln` | Skip vulnerability scanning |

---

## Scan Profiles

| Profile | Behavior |
|---------|----------|
| **`full`** (default) | All 38+ modules enabled; maximum data; longest runtime |
| **`quick`** | Throttled subdomains, port targets, and spider pages; faster execution with reduced scope |
| **`stealth`** | Excludes noisy modules (DNS brute-force, spider, cloud scanning, CI/CD, Docker); minimal network footprint |

---

## Examples

### Full Reconnaissance

```bash
xrefs0 example.com --html report.html --json data.json --pdf report.pdf --md report.md
```

### Stealth Mode

```bash
xrefs0 example.com --profile stealth --proxy socks5://127.0.0.1:9050 --retry 1
```

### Quick Scan

```bash
xrefs0 example.com --profile quick --no-screenshot --no-graph
```

### Targeted Modules

```bash
xrefs0 example.com --only-modules whois subdomains dns ssl
```

### Rate-Limited Scan

```bash
xrefs0 example.com --rate-limit 10 --delay 0.5 -T 20
```

### Custom Wordlists

```bash
xrefs0 example.com --dirs-wordlist my_dirs.txt --subs-wordlist my_subs.txt
```

### Resume Scan

```bash
xrefs0 example.com --resume
```

### Deep Scan

```bash
xrefs0 example.com --threads 100 --timeout 30 -m 500
```

### Batch Processing

```bash
xrefs0 --file domains.txt --html report_DOMAIN.html --json data_DOMAIN.json
```

### CIDR Enumeration

```bash
xrefs0 example.com --cidr 192.168.1.0/24 10.0.0.0/8
```

---

## Module Catalog

| # | Module | Description |
|---|--------|-------------|
| 01 | **WHOIS** | Registrar, creation/expiry dates, domain status |
| 02 | **Subdomain Enum** | Passive enumeration from CRT, AlienVault, HackerTarget, DNSDumpster, RapidDNS, SecurityTrails, ThreatMiner, Anubis |
| 03 | **DNS Brute-force** | Wordlist-driven subdomain discovery via DNS resolution |
| 04 | **DNS Lookup** | A, AAAA, MX, NS, TXT, CNAME, SOA, PTR records + AXFR zone transfer check |
| 05 | **Reverse DNS** | PTR record lookups + CIDR network enumeration |
| 06 | **Real IP** | CDN/Proxy bypass via 7 detection methods (MX, NS, SOA, subdomain, etc.) |
| 07 | **HTTP Probe** | Service probing, status codes, title extraction, redirect chain |
| 08 | **CDN Detection** | Cloudflare, Akamai, CloudFront, Incapsula, Fastly, StackPath |
| 09 | **Tech Detection** | 40+ fingerprint patterns — WordPress, React, Nginx, Laravel, Django, etc. |
| 10 | **JS Extraction** | Endpoint, API route, and secret extraction from JavaScript files |
| 11 | **Link Spider** | Web crawling for all discovered links (configurable depth/pages) |
| 12 | **SSL Analysis** | Certificate validity, issuer, subject, SANs, fingerprint, days remaining |
| 13 | **Mail Security** | SPF, DKIM, DMARC record presence and policy analysis |
| 14 | **Security Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc. |
| 15 | **Cookie Check** | Secure flag, HttpOnly, SameSite attribute audit |
| 16 | **CORS Check** | Wildcard origin, origin reflection, credential misconfiguration |
| 17 | **WAF Detection** | 15+ WAF signatures — Cloudflare, AWS WAF, ModSecurity, F5, etc. |
| 18 | **Port Scan** | TCP port scanning (45 tier-1 ports) with banner grabbing |
| 19 | **ASN/Geo** | ASN number, ISP, country, city, latitude/longitude |
| 20 | **Takeover Check** | 30+ cloud service fingerprints for subdomain takeover |
| 21 | **S3 Scanner** | AWS S3 bucket name permutation and accessibility check |
| 22 | **Cloud Scanner** | GCP cloud storage buckets + Azure blob containers |
| 23 | **Email Harvest** | Email address extraction from web pages and public sources |
| 24 | **Wayback Machine** | Archived URL extraction from the Wayback Machine CDX API |
| 25 | **CommonCrawl** | Indexed URL extraction from CommonCrawl |
| 26 | **Google Dorks** | 40+ targeted Google dork queries for the target domain |
| 27 | **GitHub Recon** | Code search, repository discovery, secret/credential scanning |
| 28 | **CVE Matching** | Technology-to-CVE mapping via NVD database lookup |
| 29 | **CMS Detection** | 50+ CMS fingerprints — WordPress, Drupal, Joomla, Magento, Shopify |
| 30 | **Directory Enum** | Path brute-force with 1000+ entry wordlist |
| 31 | **Swagger/OpenAPI** | API documentation endpoint discovery |
| 32 | **GraphQL** | GraphQL introspection query detection |
| 33 | **CI/CD Discovery** | 70+ CI/CD file signatures — Jenkins, GitLab CI, GitHub Actions, Terraform |
| 34 | **Docker Registry** | Exposed Docker registry detection |
| 35 | **Favicon Hash** | mmh3, MD5, SHA256 hash calculation |
| 36 | **Screenshot** | Webpage screenshot capture (requires Playwright) |
| 37 | **Graph Viz** | Interactive D3.js force-directed network graph |
| 38 | **History DB** | SQLite-backed historical tracking with `--resume` support |

---

## File Structure

```
xrefs0/                   # Project root
├── xrefs0.py             # Main entry point
├── xrefs0.bat            # Windows launcher
├── config.yaml           # API keys configuration
├── requirements.txt      # Python dependencies
├── README.md             # Project documentation
├── COMMANDS.md           # Command reference (this file)
├── wordlists/
│   ├── subdomains.txt    # 874 subdomain names
│   ├── dirs.txt          # 1011 directory paths
│   └── resolvers.txt     # 16 public DNS resolvers
└── modules/
    ├── __init__.py
    ├── subdomain_enum.py     # Passive subdomain enumeration
    ├── dns_lookup.py         # Full DNS record resolution
    ├── dns_bruteforce.py     # DNS brute-force engine
    ├── http_probe.py         # HTTP service probing
    ├── port_scan.py          # TCP port scanning
    ├── ssl_analyzer.py       # SSL/TLS certificate analysis
    ├── tech_detect.py        # Technology fingerprinting
    ├── cms_scanner.py        # CMS detection
    ├── cve_check.py          # CVE matching engine
    ├── takeover_check.py     # Subdomain takeover detection
    ├── mail_security.py      # SPF/DKIM/DMARC checks
    ├── security_headers.py   # Security header audit
    ├── cookie_check.py       # Cookie flag analysis
    ├── cors_check.py         # CORS misconfiguration check
    ├── waf_detect.py         # WAF fingerprinting
    ├── asn_geo.py            # ASN/geolocation lookup
    ├── email_harvest.py      # Email address harvesting
    ├── js_extractor.py       # JavaScript endpoint extraction
    ├── link_spider.py        # Web link spidering
    ├── wayback_scraper.py    # Wayback Machine mining
    ├── commoncrawl_scraper.py# CommonCrawl index mining
    ├── google_dorks.py       # Google dork generator
    ├── github_recon.py       # GitHub code search
    ├── dir_enum.py           # Directory brute-force
    ├── swagger_finder.py     # OpenAPI/Swagger discovery
    ├── cicd_discovery.py     # CI/CD file detection
    ├── cloud_scanner.py      # GCP/Azure storage scan
    ├── s3_scanner.py         # AWS S3 bucket scan
    ├── docker_registry.py    # Docker registry scan
    ├── real_ip.py            # CDN bypass engine
    ├── cdn_detect.py         # CDN provider detection
    ├── favicon_hash.py       # Favicon hash calculation
    ├── screenshot.py         # Page screenshot capture
    ├── graph_viz.py          # D3.js graph generator
    ├── historical.py         # SQLite history tracker
    ├── reverse_dns.py        # PTR/CIDR enumeration
    ├── output.py             # Output engine (HTML/JSON/CSV/etc.)
    └── whois_check.py        # WHOIS data retrieval
```

---

## Quick Reference

```bash
# Basic scan (auto-generates report.html + data.json)
xrefs0 fayoum.edu.eg

# Silent scan with all exports
xrefs0 example.com --silent --html report.html --json data.json --pdf report.pdf

# Stealth + proxy
xrefs0 example.com --profile stealth --proxy socks5://127.0.0.1:9050

# Targeted modules
xrefs0 example.com --only-modules whois subdomains dns ssl

# High-performance deep scan
xrefs0 example.com -T 100 -t 30 --resume

# Batch from file
xrefs0 --file domains.txt --html report_DOMAIN.html

# Display help
xrefs0 --help

# Display version
xrefs0 --version
```

---

## Connect

<p align="center">
  <a href="https://t.me/XREFS0_CHANNEL"><img src="https://img.shields.io/badge/Telegram-Channel-00d4ff?style=for-the-badge&logo=telegram&labelColor=0a0e1a" alt="Telegram Channel"/></a>
  <a href="https://t.me/MrMasaOfficial"><img src="https://img.shields.io/badge/Telegram-Contact-ff4444?style=for-the-badge&logo=telegram&labelColor=0a0e1a" alt="Telegram Contact"/></a>
  <a href="https://www.youtube.com/@XREFS0"><img src="https://img.shields.io/badge/YouTube-Channel-ff0000?style=for-the-badge&logo=youtube&labelColor=0a0e1a" alt="YouTube"/></a>
  <br>
  <a href="https://github.com/XREFS0"><img src="https://img.shields.io/badge/GitHub-Organization-6e5494?style=for-the-badge&logo=github&labelColor=0a0e1a" alt="GitHub"/></a>
  <a href="https://www.linkedin.com/in/mrmasaofficial"><img src="https://img.shields.io/badge/LinkedIn-Profile-0077b5?style=for-the-badge&logo=linkedin&labelColor=0a0e1a" alt="LinkedIn"/></a>
  <a href="http://xrefs0.com/"><img src="https://img.shields.io/badge/Web-xrefs0.com-00ff88?style=for-the-badge&logo=google-chrome&labelColor=0a0e1a" alt="Website"/></a>
</p>

---

<p align="center">
  <b>XREFS0</b> — Cyber Intelligence & Domain Reconnaissance<br>
  <i>Coded by MASA</i> | Protocol: Dark Recon
</p>
