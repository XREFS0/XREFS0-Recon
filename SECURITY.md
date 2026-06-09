# Security Policy

XREFS0 is a cybersecurity reconnaissance tool designed for authorized security assessments. This document outlines the security practices for the project and how to responsibly report vulnerabilities.

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.0.x   | ✅ Active development & security patches |
| < 2.0   | ❌ No longer supported |

---

## Reporting a Vulnerability

XREFS0 is a security tool that interfaces with external systems. If you discover a vulnerability in the tool itself — including code execution flaws, data exposure, authentication bypass, or dependency vulnerabilities — please report it **privately** before disclosing it publicly.

### How to Report

- **Telegram:** [@MrMasaOfficial](https://t.me/MrMasaOfficial)
- **Do NOT** open a public GitHub issue for security vulnerabilities.

### What to Include

- **Description** of the vulnerability and potential impact
- **Steps to reproduce** — minimal, reproducible example
- **Affected version(s)**
- **Suggested fix** (if applicable)
- **Your contact** for follow-up (Telegram handle or email)

### Response Timeline

| Timeframe | Action |
|-----------|--------|
| 48 hours  | Acknowledgment of receipt |
| 7 days    | Initial assessment and severity classification |
| 30 days   | Fix released or mitigation plan communicated |

---

## Responsible Disclosure

We follow a coordinated disclosure process:

1. Reporter submits vulnerability details privately.
2. Project maintainer acknowledges and assesses the report.
3. A fix is developed and tested.
4. The fix is released, and the reporter is credited (if desired).
5. Public disclosure occurs after users have had time to update.

We aim to release a fix within **30 days** of confirmation for critical/high severity issues.

---

## Security Best Practices for Users

When using XREFS0, follow these guidelines:

- **Authorized use only** — Only scan domains you own or have explicit permission to test.
- **Use proxies** — For sensitive engagements, route traffic through a proxy or VPN.
- **Limit scope** — Use `--only-modules`, `--max-subdomains`, and `--profile` to control scan intensity.
- **Review output carefully** — JSON exports contain raw data; handle reports responsibly.
- **Keep updated** — Always use the latest version for security fixes.

---

## Dependency Security

- Regularly reviewed and updated to patch known CVEs.
- Automated dependency scanning is performed when possible.
- If you identify a vulnerable dependency, report it via the channels above.

---

## Legal Notice

XREFS0 is intended **exclusively** for authorized security assessments, educational purposes, and defensive cybersecurity research. Unauthorized use of this tool against systems you do not own or lack explicit written permission to test may violate applicable laws. The authors assume no liability for misuse.

---

## Contact

- **Telegram Channel:** [@XREFS0_CHANNEL](https://t.me/XREFS0_CHANNEL)
- **Telegram Contact:** [@MrMasaOfficial](https://t.me/MrMasaOfficial)
- **Website:** [xrefs0.com](http://xrefs0.com/)
