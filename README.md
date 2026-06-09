<p align="center">
  <img src="https://img.shields.io/badge/XREFS0-v2.0-ff4444?style=for-the-badge&labelColor=0a0e1a" alt="XREFS0 v2.0"/>
  <img src="https://img.shields.io/badge/Modules-38%2B-00d4ff?style=for-the-badge&labelColor=0a0e1a" alt="38+ Modules"/>
  <img src="https://img.shields.io/badge/License-MIT-00ff88?style=for-the-badge&labelColor=0a0e1a" alt="MIT License"/>
</p>

<h1 align="center">XREFS0</h1>
<p align="center"><b>Cyber Intelligence & Domain Reconnaissance Platform</b></p>
<p align="center">
  <i>Coded by <a href="https://github.com/XREFS0">MASA</a></i><br>
  <b>Protocol:</b> Dark Recon
</p>

---

## Overview

XREFS0 is a comprehensive domain reconnaissance platform that integrates **38+ reconnaissance modules** into a single, streamlined CLI tool. It performs WHOIS lookups, subdomain enumeration across 8 free sources, full DNS analysis (A/AAAA/MX/NS/TXT/CNAME/SOA/AXFR), port scanning, technology fingerprinting, CMS detection, vulnerability assessment (SQLi / XSS / Open Redirect), and more — entirely from free, public sources with **zero API keys required**.

Designed for security researchers, penetration testers, and blue teams who need deep, multi-vector reconnaissance without the overhead of managing disparate tools.

---

## Features

- **38+ Reconnaissance Modules** — WHOIS, subdomains (8 sources), DNS, SSL, WAF, ports, ASN, CMS (50+), S3, cloud, email, JS extraction, vulnerability scanning, and more
- **Zero API Keys Required** — All sources are free, no registration needed
- **Per-Subdomain Deep Scanning** — Port scan, SSL, screenshot, takeover check, dir enum, JS extract, favicon hash — applied to every discovered subdomain
- **Parallel Execution Architecture** — Independent modules run concurrently across 6 orchestrated groups, reducing scan time by 60%+
- **Severity-Graded Findings** — Results categorized as CRITICAL, HIGH, MEDIUM, INFO for clear prioritization
- **Basic Vulnerability Assessment** — SQLi reflection, reflected XSS, open redirect, `.env` exposure checks
- **11 Export Formats** — Terminal (Rich), HTML (dark cyber theme), JSON, YAML, CSV, XLSX, PDF, Markdown, screenshots, interactive D3.js graph, SQLite history database
- **Batch & CIDR Scanning** — Scan multiple domains from a file or enumerate entire CIDR ranges
- **Scan Profiles** — `full`, `quick`, `stealth`
- **Proxy Support** — HTTP, HTTPS, SOCKS5
- **Resume Capability** — SQLite-backed history database with `--resume`
- **Rate Limiting & Retry** — Configurable delay, rate limit, and retry with exponential backoff
- **`--only-modules`** — Execute a subset of modules for targeted scanning
- **`--compact`** — Streamlined terminal output mode

---

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Verify installation
python xrefs0.py --version
```

---

## Quick Start

```bash
# Basic scan
xrefs0 example.com

# Full export with HTML report + JSON data
xrefs0 example.com --html report.html --json data.json

# Stealth scan through proxy
xrefs0 example.com --profile stealth --proxy socks5://127.0.0.1:9050

# Targeted module execution
xrefs0 example.com --only-modules whois subdomains dns ssl

# Batch scan multiple domains
xrefs0 --file domains.txt --html report_DOMAIN.html
```

---

## Modules

| Module | Description |
|--------|-------------|
| whois | Registrar, creation/expiry dates, domain status |
| subdomains | Subdomain enumeration from 8 free public sources |
| dns_bruteforce | DNS brute-force with customizable wordlist |
| dns | Full DNS record resolution (A/AAAA/MX/NS/TXT/CNAME/SOA) + AXFR zone transfer check |
| reverse_dns | PTR lookups + CIDR network enumeration |
| real_ip | CDN/proxy bypass — real origin IP detection (7 methods) |
| http | HTTP service probing, CDN detection, technology fingerprinting |
| js_extract | JavaScript endpoint and secret extraction |
| spider | Web link crawling for endpoint discovery |
| ssl | SSL/TLS certificate analysis (validity, SANs, issuer, expiry) |
| mail | Mail security posture — SPF, DKIM, DMARC |
| security | Security headers audit, cookie flags, CORS misconfiguration |
| waf | Web application firewall detection (15+ signatures) |
| ports | TCP port scanning across 1000 ports with banner grabbing |
| asn | ASN, ISP, country, city, geolocation lookup |
| takeover | Subdomain takeover vulnerability check across 30+ cloud services |
| s3 | AWS S3 bucket enumeration and accessibility check |
| cloud | GCP cloud storage + Azure blob container scanning |
| emails | Email address harvesting from public sources |
| wayback | Wayback Machine archived URL mining |
| commoncrawl | CommonCrawl index URL extraction |
| dorks | Google dork query generation (40+ patterns) |
| github | GitHub code and secret search for exposed credentials |
| cve | CVE matching against detected technology stack |
| cms | CMS fingerprinting (WordPress, Drupal, Joomla, etc.) |
| dirb | Directory and file brute-force against live hosts |
| swagger | OpenAPI/Swagger/GraphQL endpoint discovery |
| cicd | CI/CD configuration file discovery (70+ patterns) |
| docker | Docker registry exposure scanning |
| favicon | Favicon hash calculation (mmh3, md5, SHA256) |
| screenshot | Webpage screenshot capture |
| graph | Interactive D3.js network graph visualization |

---

## Output Formats

| Flag | Format | Description |
|------|--------|-------------|
| `--html FILE` | HTML | Professional dark-theme report with collapsible sections |
| `--json FILE` | JSON | Raw structured data export |
| `--yaml FILE` | YAML | YAML data export |
| `--csv FILE` | CSV | Tabular subdomain data |
| `--xlsx FILE` | XLSX | Excel spreadsheet (multiple sheets) |
| `--pdf FILE` | PDF | PDF report (requires puppeteer) |
| `--markdown FILE` | Markdown | Lightweight text report |

---

## Scan Profiles

| Profile | Description |
|---------|-------------|
| `full` | All modules enabled, maximum coverage (default) |
| `quick` | Throttled subdomains, ports, and spider; faster execution |
| `stealth` | Minimal footprint — excludes brute-force, crawling, cloud scanning, CI/CD, docker |

---

## Connect

<p align="center">
  <a href="https://t.me/XREFS0_CHANNEL"><img src="https://img.shields.io/badge/Telegram-Channel-00d4ff?style=for-the-badge&logo=telegram&labelColor=0a0e1a" alt="Telegram Channel"/></a>
  <a href="https://t.me/MrMasaOfficial"><img src="https://img.shields.io/badge/Telegram-Contact-ff4444?style=for-the-badge&logo=telegram&labelColor=0a0e1a" alt="Telegram Contact"/></a>
  <a href="https://www.youtube.com/@XREFS0"><img src="https://img.shields.io/badge/YouTube-Channel-ff0000?style=for-the-badge&logo=youtube&labelColor=0a0e1a" alt="YouTube Channel"/></a>
  <br>
  <a href="https://github.com/XREFS0"><img src="https://img.shields.io/badge/GitHub-Organization-6e5494?style=for-the-badge&logo=github&labelColor=0a0e1a" alt="GitHub Org"/></a>
  <a href="https://www.linkedin.com/in/mrmasaofficial"><img src="https://img.shields.io/badge/LinkedIn-Profile-0077b5?style=for-the-badge&logo=linkedin&labelColor=0a0e1a" alt="LinkedIn"/></a>
  <a href="http://xrefs0.com/"><img src="https://img.shields.io/badge/Web-xrefs0.com-00ff88?style=for-the-badge&logo=google-chrome&labelColor=0a0e1a" alt="Website"/></a>
</p>

---

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for full terms.

You are free to use, modify, distribute, and sublicense this software for any purpose, including commercial applications, provided the original copyright notice is included.

---

<p align="center">
  <b>XREFS0</b> — Cyber Intelligence & Domain Reconnaissance<br>
  <i>Coded by MASA</i> | Protocol: Dark Recon
</p>
