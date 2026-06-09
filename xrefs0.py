#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, io, time, random, argparse, yaml, json, warnings
warnings.filterwarnings("ignore", category=Warning)

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import ThreadPoolExecutor as TPoolExecutor, TimeoutError as TTimeoutError

from modules.subdomain_enum import SubdomainEnumerator
from modules.dns_lookup import DNSLookup
from modules.real_ip import RealIPFinder
from modules.cdn_detect import CDNDetector
from modules.whois_check import WHOISChecker
from modules.ssl_analyzer import SSLAnalyzer
from modules.http_probe import HTTPProber
from modules.tech_detect import TechDetector
from modules.favicon_hash import FaviconHash
from modules.security_headers import SecurityHeadersChecker
from modules.cookie_check import CookieChecker
from modules.cors_check import CORSChecker
from modules.mail_security import MailSecurityChecker
from modules.takeover_check import TakeoverChecker
from modules.s3_scanner import S3Scanner
from modules.port_scan import PortScanner, TIER1_PORTS
from modules.asn_geo import ASNGeoLookup
from modules.email_harvest import EmailHarvester
from modules.google_dorks import GoogleDorksGenerator
from modules.github_recon import GitHubRecon
from modules.wayback_scraper import WaybackScraper
from modules.commoncrawl_scraper import CommonCrawlScraper
from modules.dir_enum import DirEnumerator
from modules.cve_check import CVEChecker
from modules.graph_viz import GraphVizGenerator
from modules.screenshot import ScreenshotTaker
from modules.output import OutputEngine
from modules.dns_bruteforce import DNSBruteforcer
from modules.js_extractor import JSExtractor
from modules.link_spider import LinkSpider
from modules.waf_detect import WAFDetector
from modules.cloud_scanner import CloudScanner
from modules.swagger_finder import SwaggerFinder
from modules.cicd_discovery import CICDDiscovery
from modules.cms_scanner import CMSScanner
from modules.docker_registry import DockerRegistryScanner
from modules.reverse_dns import ReverseDNS
from modules.historical import HistoricalTracker

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.style import Style
    from rich.table import Table
    from rich.box import DOUBLE_EDGE, HEAVY
    from rich.layout import Layout
    console = Console()
    HAS_RICH = True
except Exception:
    HAS_RICH = False
    console = None

CREEPY_QUOTES = [
    "Not all doors should be opened. You have been warned.",
    "The silence before the scan is always the loudest.",
    "Every packet carries a secret. Every response tells a lie.",
    "What you seek is also seeking you.",
    "The void has been watching since before you existed.",
    "The network remembers. Even after the logs are gone, it remembers.",
    "Somewhere out there, a server just noticed you.",
    "The deeper you dig, the darker it gets. Keep going.",
    "Every system has a heartbeat. Listen carefully.",
    "You are not the first. You will not be the last. But you are the only one being watched.",
    "Darkness is not the absence of light. It is the presence of something else.",
    "The target knows you are here now.",
    "There are things in the dark that prefer to stay hidden.",
    "What is found can never be unfound.",
    "You cannot escape what you have already awakened.",
]

MODULE_COLORS = {
    "WHOIS": "bold red", "DNS": "bold red", "DNS_Brute": "bold red",
    "Ports": "bold red", "Directories": "bold red", "Reverse_DNS": "bold red", "Vuln": "bold red",
    "Subdomains": "bright_yellow", "S3": "bright_yellow", "Cloud": "bright_yellow",
    "Dorks": "bright_yellow", "Emails": "bright_yellow", "Takeover": "bright_yellow",
    "SSL": "cyan", "Security": "cyan", "Mail": "cyan", "WAF": "cyan",
    "CMS": "cyan", "Swagger": "cyan", "Favicon": "cyan", "Real_IP": "cyan",
    "HTTP": "bright_cyan", "JS_Extract": "bright_cyan", "Spider": "bright_cyan",
    "Wayback": "bright_cyan", "CommonCrawl": "bright_cyan", "GitHub": "bright_cyan",
    "CVE": "bright_cyan", "CI/CD": "bright_cyan", "Docker": "bright_cyan",
    "Graph": "bright_cyan", "Screenshots": "bright_cyan", "ASN": "magenta",
}

def rnd_quote():
    return random.choice(CREEPY_QUOTES)

SKULL = """
  ░▒▓█ XREFS0 █▓▒░
  Cyber Intelligence & Domain Recon Platform

  Coded by MASA
"""

class XREFS0:
    def __init__(self):
        self.args = None
        self.config = {}
        self.data = {}
        self.start_time = None
        self.proxies = None
        self.history = None
        self.scan_id = None
        self.module_times = {}
        self._findings = []
        self._module_status = {}
        self._api_cache = {}

    def add_finding(self, severity, category, message, detail=""):
        self._findings.append({"severity": severity, "category": category, "message": message, "detail": detail})

    def _print_findings(self):
        if not self._findings:
            return
        sev_icon = {"critical": "!!", "high": "!", "medium": "~", "info": "i", "ok": "✓"}
        sev_label = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "info": "INFO", "ok": "OK"}
        sev_border = {"critical": "red", "high": "yellow", "medium": "blue", "info": "dim white", "ok": "green"}
        for sev in ["critical", "high", "medium", "info", "ok"]:
            items = [f for f in self._findings if f["severity"] == sev]
            if not items:
                continue
            if console and HAS_RICH:
                tbl = Table.grid(padding=(0, 1))
                tbl.add_column(style="white", ratio=1)
                for f in items:
                    cat_color = {"Network": "red", "Web": "cyan", "Mail": "yellow", "DNS": "green", "Cloud": "blue", "SSL": "magenta", "Vuln": "bold red"}.get(f["category"], "white")
                    tbl.add_row(f"[{sev_border[sev]}][{sev_icon[sev]}][/] [{cat_color}]{f['category']:12s}[/] {f['message']}")
                panel = Panel(tbl, title=f"[{sev_border[sev]}]{sev_label[sev]}[/]", border_style=sev_border[sev].replace("dim ", ""), box=HEAVY, padding=(1, 2))
                console.print(panel)
            else:
                print(f"\n  [{sev_label[sev]}]")
                for f in items:
                    print(f"    [{sev_icon[sev]}] {f['category']:12s} {f['message']}")

    def _get_live_hosts(self, d):
        live = []
        for sub, h in d.get("http", {}).items():
            if h.get("alive") and h.get("url"):
                live.append((sub, h["url"]))
        return live

    def _get_all_ips(self, d):
        ips = set()
        for sub_data in d.get("dns", {}).values():
            if isinstance(sub_data, dict):
                for a in sub_data.get("A", []):
                    if a and a != "0.0.0.0":
                        ips.add(a)
                for a in sub_data.get("AAAA", []):
                    if a and a != "0.0.0.0":
                        ips.add(a)
        return list(ips)

    def run(self):
        parser = argparse.ArgumentParser(prog="xrefs0", add_help=False)

        parser.add_argument("domain", nargs="?", help="Target domain or URL to scan")
        parser.add_argument("--file", "-f", help="File containing domains to scan (one per line)")
        parser.add_argument("--help", "-h", action="store_true", help="Show this help message")
        parser.add_argument("--version", "-v", action="store_true", help="Show version information")
        parser.add_argument("--config", "-c", default="config.yaml", help="API keys config file")
        parser.add_argument("--silent", "-s", action="store_true", help="Silent mode (no animations)")
        parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode (minimal output)")
        parser.add_argument("--compact", action="store_true", help="Compact output mode")
        parser.add_argument("--log", "-l", help="Log file output")

        parser.add_argument("--html", help="Export HTML report")
        parser.add_argument("--json", help="Export JSON data")
        parser.add_argument("--yaml", "-y", help="Export YAML data")
        parser.add_argument("--csv", help="Export CSV data")
        parser.add_argument("--xlsx", help="Export XLSX spreadsheet")
        parser.add_argument("--pdf", help="Export PDF report")
        parser.add_argument("--markdown", "-md", help="Export Markdown report")

        parser.add_argument("--threads", "-T", type=int, default=50, help="Thread count (default: 50)")
        parser.add_argument("--timeout", "-t", type=int, default=10, help="Request timeout in seconds (default: 10)")
        parser.add_argument("--max-subdomains", "-m", type=int, default=0, help="Max subdomains to process (0 = all)")
        parser.add_argument("--profile", "-p", choices=["quick", "full", "stealth"], default="full", help="Scan profile: quick, full, stealth (default: full)")
        parser.add_argument("--delay", "-d", type=float, default=0, help="Delay between requests in seconds")
        parser.add_argument("--rate-limit", "-rl", type=int, default=0, help="Max requests per second")
        parser.add_argument("--proxy", help="Proxy URL (e.g. socks5://127.0.0.1:9050)")
        parser.add_argument("--retry", type=int, default=2, help="Retry attempts on failure (default: 2)")
        parser.add_argument("--resolvers", nargs="+", default=["8.26.56.26", "208.67.222.222", "9.9.9.9", "1.1.1.1", "8.8.8.8"], help="Custom DNS resolvers (fallbacks after system DNS)")
        parser.add_argument("--resume", action="store_true", help="Resume last scan for this domain")
        parser.add_argument("--cidr", nargs="+", help="CIDR ranges to scan (e.g. 192.168.1.0/24)")
        parser.add_argument("--no-history", action="store_true", help="Skip saving to history database")
        parser.add_argument("--no-http", action="store_true", help="Skip HTTP probing")
        parser.add_argument("--no-port", action="store_true", help="Skip port scanning")
        parser.add_argument("--no-dirb", action="store_true", help="Skip directory enumeration")
        parser.add_argument("--no-screenshot", action="store_true", help="Skip screenshots")
        parser.add_argument("--no-graph", action="store_true", help="Skip graph generation")
        parser.add_argument("--no-dns-brute", action="store_true", help="Skip DNS brute-force")
        parser.add_argument("--no-js-extract", action="store_true", help="Skip JS extraction")
        parser.add_argument("--no-spider", action="store_true", help="Skip link spider")
        parser.add_argument("--no-waf", action="store_true", help="Skip WAF detection")
        parser.add_argument("--no-cloud", action="store_true", help="Skip cloud storage scan")
        parser.add_argument("--no-swagger", action="store_true", help="Skip API docs discovery")
        parser.add_argument("--no-cicd", action="store_true", help="Skip CI/CD discovery")
        parser.add_argument("--no-cms", action="store_true", help="Skip CMS detection")
        parser.add_argument("--no-docker", action="store_true", help="Skip Docker registry scan")
        parser.add_argument("--no-reverse-dns", action="store_true", help="Skip reverse DNS")
        parser.add_argument("--no-wayback", action="store_true", help="Skip Wayback Machine scraping")
        parser.add_argument("--no-commoncrawl", action="store_true", help="Skip CommonCrawl scraping")
        parser.add_argument("--no-dorks", action="store_true", help="Skip Google dorks generation")
        parser.add_argument("--no-github", action="store_true", help="Skip GitHub recon")
        parser.add_argument("--no-cve", action="store_true", help="Skip CVE matching")
        parser.add_argument("--no-whois", action="store_true", help="Skip WHOIS lookup")
        parser.add_argument("--no-subdomains", action="store_true", help="Skip subdomain enumeration")
        parser.add_argument("--no-dns", action="store_true", help="Skip DNS lookup")
        parser.add_argument("--no-real-ip", action="store_true", help="Skip real IP detection")
        parser.add_argument("--no-ssl", action="store_true", help="Skip SSL analysis")
        parser.add_argument("--no-mail", action="store_true", help="Skip mail security check")
        parser.add_argument("--no-security", action="store_true", help="Skip security headers scan")
        parser.add_argument("--no-asn", action="store_true", help="Skip ASN/Geo lookup")
        parser.add_argument("--no-takeover", action="store_true", help="Skip takeover check")
        parser.add_argument("--no-s3", action="store_true", help="Skip S3 bucket scan")
        parser.add_argument("--no-emails", action="store_true", help="Skip email harvesting")
        parser.add_argument("--no-favicon", action="store_true", help="Skip favicon hash")
        parser.add_argument("--no-vuln", action="store_true", help="Skip vulnerability scan")
        parser.add_argument("--dirs-wordlist", help="Custom directory wordlist path")
        parser.add_argument("--subs-wordlist", help="Custom subdomain wordlist path")
        parser.add_argument("--only-modules", nargs="+", help="Run only these modules (space separated)")

        self.args = parser.parse_args()

        if self.args.version:
            self.show_version()
            return

        if self.args.help or not (self.args.domain or self.args.file):
            self.show_help(parser)
            return

        if self.args.quiet:
            self.args.silent = True

        if self.args.proxy:
            os.environ["HTTP_PROXY"] = self.args.proxy
            os.environ["HTTPS_PROXY"] = self.args.proxy
            self.proxies = {"http": self.args.proxy, "https": self.args.proxy}

        domains_to_scan = []
        if self.args.file:
            try:
                with open(self.args.file, "r") as f:
                    domains_to_scan = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"Error reading domain file: {e}")
                return
        elif self.args.domain:
            domains_to_scan = [self.args.domain.strip().lower()]

        if not domains_to_scan:
            print("No domains to scan.")
            return

        for domain_raw in domains_to_scan:
            for prefix in ["https://", "http://", "www."]:
                if domain_raw.startswith(prefix):
                    domain_raw = domain_raw[len(prefix):]
            domain_raw = domain_raw.split("/")[0].split("?")[0].split("#")[0]
            self.args.domain = domain_raw

            self.start_time = time.time()
            self.config = self._load_config(self.args.config)
            self.data = self._init_data()
            self._findings = []

            if len(domains_to_scan) > 1:
                self._log(f"\n{'='*50}\nScanning domain {domains_to_scan.index(domain_raw)+1}/{len(domains_to_scan)}: {domain_raw}\n{'='*50}")

            if not self.args.html:
                self.args.html = "report.html"
            if not self.args.json:
                self.args.json = "data.json"
            self._scan_setup()
            self._execute_scan()
            self._show_results()
            self._show_final_report()

            if self.args.log:
                self._write_log(self.args.log)

    def _scan_setup(self):
        self.config.setdefault("settings", {})
        self.config["settings"]["threads"] = self.args.threads
        self.config["settings"]["timeout"] = self.args.timeout
        self.config["settings"]["max_subdomains"] = self.args.max_subdomains
        self.config["settings"]["delay"] = self.args.delay
        self.config["settings"]["rate_limit"] = self.args.rate_limit
        self.config["settings"]["retry"] = self.args.retry
        self.config["settings"]["resolvers"] = self.args.resolvers
        self.config["settings"]["proxy"] = self.args.proxy
        self.config["settings"]["proxies"] = self.proxies

        if not self.args.no_history:
            self.history = HistoricalTracker()
            if self.args.resume:
                self._log("Attempting to resume previous scan...")
                prev = self.history.resume_data(self.args.domain)
                if prev:
                    self.data = prev
                    self._log(f"Resumed previous scan data for {self.args.domain}")

        self._print_startup()

    def _print_startup(self):
        if self.args.silent:
            return
        if console and HAS_RICH:
            banner_text = Text("""
  ░▒▓█ XREFS0 █▓▒░
  Cyber Intelligence & Domain Recon Platform

  Coded by MASA
""", style="bold red")
            panel = Panel(banner_text, border_style="dark_red", box=DOUBLE_EDGE, title="[dark_red]INITIALIZING[/]", title_align="left")
            console.print(panel)
            console.print(f"\n  [italic dark_red]\"{rnd_quote()}\"[/]\n")
            console.print(f"  [white]Domain:[/] [bold yellow]{self.args.domain}[/]")
            console.print(f"  [white]Profile:[/] [yellow]{self.args.profile}[/]")
            console.print(f"  [white]Threads:[/] [cyan]{self.args.threads}[/]")
            console.print(f"  [white]Timeout:[/] [cyan]{self.args.timeout}s[/]")
            if self.args.proxy:
                console.print(f"  [white]Proxy:[/] [cyan]{self.args.proxy}[/]")
            if self.args.compact:
                console.print(f"  [white]Mode:[/] [yellow]Compact[/]")
        else:
            if console:
                console.print(SKULL)
                time.sleep(0.5)
            self._log(f"Domain: {self.args.domain}")
            self._log(f"Profile: {self.args.profile}")
            self._log(f"Threads: {self.args.threads}")
            self._log(f"Timeout: {self.args.timeout}s")
            if self.args.proxy:
                self._log(f"Proxy: {self.args.proxy}")

    def _log(self, msg):
        prefix = f"[{datetime.now().strftime('%H:%M:%S')}]"
        log_line = f"{prefix} {msg}"
        if console and HAS_RICH and not self.args.silent:
            if msg.startswith("  "):
                content = msg[2:]
                if any(w in content for w in ["VULNERABLE", "EXPOSED"]):
                    styled = f"[bold red]{content}[/]"
                elif any(w in content for w in ["Found", "found"]):
                    styled = f"[bold green]{content}[/]"
                elif any(w in content for w in ["No", "Missing", "timed out", "failed"]):
                    styled = f"[yellow]{content}[/]"
                elif "ERROR" in content:
                    styled = f"[bold red]{content}[/]"
                else:
                    styled = f"[white]{content}[/]"
                console.print(f"  [dim white]{prefix}[/] {styled}")
            else:
                console.print(f"  [dim white]{prefix}[/] [white]{msg}[/]")
        elif console and not self.args.silent:
            console.print(f"  {log_line}")
        else:
            print(log_line, flush=True)

    def _log_step(self, name, msg):
        if self.args.compact and not self.args.silent:
            if console and HAS_RICH:
                color = MODULE_COLORS.get(name, "white")
                console.print(f"  [{color}]■[/] [bold]{name}[/] — {msg}")
            return
        if console and HAS_RICH and not self.args.silent:
            color = MODULE_COLORS.get(name, "white")
            now = datetime.now().strftime('%H:%M:%S')
            console.print(f"  [dim white][{now}][/] [dark_red]────[/] [{color}]▸ {name} ◂[/] [dark_red]────[/]")
            console.print(f"  [dim white][{now}][/]  {msg}")
        else:
            self._log(f"[{name}] {msg}")

    def _time_module(self, name):
        self.module_times[name] = time.time()

    def _end_module(self, name):
        if name in self.module_times:
            elapsed = int((time.time() - self.module_times[name]) * 1000)
            if self.history and self.scan_id and not self.args.no_history:
                self.history.save_module_result(self.scan_id, name, "completed", elapsed)
            return elapsed
        return 0

    def _execute_scan(self):
        d = self.data
        a = self.args
        cfg = self.config
        subdomains = [a.domain]

        if self.history and not self.args.no_history:
            self.scan_id = self.history.save_scan(a.domain, 0, [], d)

        only_modules = a.only_modules if a.only_modules else None
        valid_modules = {"whois","subdomains","dns_bruteforce","dns","reverse_dns","real_ip","http","js_extract","spider","ssl","mail","security","waf","ports","asn","takeover","s3","cloud","emails","wayback","commoncrawl","dorks","github","cve","cms","dirb","swagger","cicd","docker","favicon","screenshot","graph","vuln"}
        if only_modules:
            invalid = [m for m in only_modules if m not in valid_modules]
            if invalid:
                self._log(f"  Unknown modules: {', '.join(invalid)}")
                self._log(f"  Valid: {', '.join(sorted(valid_modules))}")
        def should_run(m):
            return m in only_modules if only_modules else True

        profile = a.profile

        # ========== GROUP A: WHOIS + Subdomains + Mail + Dorks (parallel) ==========
        def run_whois():
            if should_run("whois") and not a.no_whois:
                self._time_module("WHOIS")
                self._log_step("WHOIS", "Extracting registrar data...")
                try:
                    w = WHOISChecker(a.domain, timeout=a.timeout)
                    d["whois"] = w.lookup()
                    if not d["whois"].get("is_registered") and not d["whois"].get("registrar"):
                        for _ in range(a.retry):
                            time.sleep(1)
                            d["whois"] = w.lookup()
                            if d["whois"].get("registrar"):
                                break
                    if d["whois"].get("registrar"):
                        self._log(f"  Registrar: {d['whois']['registrar']}")
                    elif d["whois"].get("is_registered"):
                        self._log("  WHOIS data retrieved (registrar unknown)")
                    else:
                        self._log("  WHOIS lookup failed or domain unregistered")
                except Exception as e:
                    self._log(f"  WHOIS error: {e}")
                    d["whois"] = {}
                self._end_module("WHOIS")

        def run_subdomains():
            nonlocal subdomains
            if should_run("subdomains") and not a.no_subdomains:
                self._time_module("Subdomains")
                self._log_step("Subdomains", "Enumerating from 8 free sources...")
                enumerator = SubdomainEnumerator(a.domain, config=cfg)
                subdomains = enumerator.enumerate_all()
                max_sub = a.max_subdomains if a.max_subdomains > 0 else len(subdomains)
                subdomains = subdomains[:max_sub]
                d["subdomains"] = subdomains
                self._log(f"  Found {len(subdomains)} subdomains")
                self.add_finding("info", "DNS", f"{len(subdomains)} subdomains discovered")
                self._end_module("Subdomains")

        def run_mail():
            if should_run("mail") and not a.no_mail:
                self._time_module("Mail")
                self._log_step("Mail", "Checking mail security...")
                mail_checker = MailSecurityChecker(a.domain, timeout=a.timeout)
                d["mail_security"] = mail_checker.check_all()
                mail = d["mail_security"]
                if not mail.get("spf", {}).get("present"):
                    self.add_finding("high", "Mail", "SPF record missing")
                if not mail.get("dmarc", {}).get("present"):
                    self.add_finding("high", "Mail", "DMARC policy missing")
                if not mail.get("dkim", {}).get("present"):
                    self.add_finding("medium", "Mail", "DKIM record missing")
                self._log("  Mail security analyzed")
                self._end_module("Mail")

        def run_dorks():
            if should_run("dorks") and not a.no_dorks:
                self._time_module("Dorks")
                self._log_step("Dorks", "Generating Google dorks...")
                try:
                    dorks = GoogleDorksGenerator(a.domain)
                    d["google_dorks"] = dorks.generate()
                    self._log(f"  {len(d['google_dorks'])} dorks generated")
                except Exception as e:
                    self._log(f"  Dorks failed: {e}")
                    d["google_dorks"] = []
                self._end_module("Dorks")

        with ThreadPoolExecutor(max_workers=4) as ex:
            for f in as_completed([ex.submit(fn) for fn in [run_whois, run_subdomains, run_mail, run_dorks]]):
                try:
                    f.result()
                except Exception:
                    pass

        if not subdomains:
            subdomains = [a.domain]

        # --- DNS Brute-force ---
        if should_run("dns_bruteforce") and not a.no_dns_brute and profile != "stealth":
            self._time_module("DNS_Brute")
            self._log_step("DNS_Brute", "Brute-forcing subdomains via DNS...")
            bf = DNSBruteforcer(a.domain, wordlist=a.subs_wordlist or "", resolvers=a.resolvers, timeout=min(a.timeout, 5))
            brute_results = bf.brute(max_workers=a.threads)
            brute_subs = [r["hostname"] for r in brute_results]
            new_subs = [s for s in brute_subs if s not in set(subdomains)]
            if new_subs:
                subdomains.extend(new_subs)
                d["subdomains"] = subdomains
                self._log(f"  DNS brute-force found {len(new_subs)} new subdomains")
            else:
                self._log("  DNS brute-force found no new subdomains")
            self._end_module("DNS_Brute")

        # ========== GROUP B: DNS + Reverse DNS + Real IP (parallel) ==========
        def run_dns():
            if should_run("dns") and not a.no_dns:
                self._time_module("DNS")
                self._log_step("DNS", "Resolving DNS records...")
                dns = DNSLookup(a.domain, timeout=a.timeout, resolvers=a.resolvers)
                d["dns"] = dns.lookup_all(subdomains)
                try:
                    ns_records = d["dns"].get(a.domain, {}).get("NS", [])
                    if ns_records:
                        axfr = dns.check_axfr(ns_records)
                        if axfr:
                            d["axfr"] = axfr
                            self._log("  Zone Transfer VULNERABLE!")
                            self.add_finding("critical", "DNS", "Zone transfer is enabled!", "ns: " + ", ".join(ns_records))
                except Exception:
                    pass
                self._log("  DNS records resolved")
                self._end_module("DNS")

        def run_reverse_dns():
            if should_run("reverse_dns") and not a.no_reverse_dns:
                self._time_module("Reverse_DNS")
                self._log_step("Reverse_DNS", "Performing reverse DNS lookups...")
                if a.cidr:
                    rdns = ReverseDNS(timeout=a.timeout)
                    all_ptr = {}
                    for cidr in a.cidr:
                        try:
                            ptr = rdns.enumerate_network(cidr)
                            all_ptr[cidr] = ptr
                            self._log(f"  CIDR {cidr}: {len(ptr)} PTR records")
                        except Exception as e:
                            self._log(f"  CIDR {cidr} scan failed: {e}")
                    d["reverse_dns"] = all_ptr
                else:
                    all_ips = self._get_all_ips(d)
                    if all_ips:
                        rdns = ReverseDNS(timeout=a.timeout)
                        ptr_results = rdns.lookup(list(set(all_ips))[:100])
                        d["reverse_dns"] = ptr_results
                        self._log(f"  Resolved {len(ptr_results)} PTR records")
                self._end_module("Reverse_DNS")

        def run_real_ip():
            if should_run("real_ip") and not a.no_real_ip:
                self._time_module("Real_IP")
                self._log_step("Real_IP", "Bypassing CDN proxies...")
                ip_finder = RealIPFinder(a.domain, timeout=a.timeout)
                d["real_ip"] = ip_finder.find(subdomains)
                real_ips = d["real_ip"].get("ips", [])
                if real_ips:
                    self._log(f"  Real IPs: {', '.join(real_ips[:3])}")
                    self.add_finding("info", "Network", f"Real IPs behind CDN: {', '.join(real_ips[:3])}")
                self._end_module("Real_IP")

        with ThreadPoolExecutor(max_workers=3) as ex:
            for f in as_completed([ex.submit(fn) for fn in [run_dns, run_reverse_dns, run_real_ip]]):
                try:
                    f.result()
                except Exception:
                    pass

        # ========== GROUP C: HTTP + SSL + Port (parallel) ==========
        http_results = {}
        cdn_results = {}
        tech_results = {}
        ssl_results = {}
        port_results = []

        def run_http():
            nonlocal http_results, cdn_results, tech_results
            if not a.no_http and should_run("http"):
                self._time_module("HTTP")
                self._log_step("HTTP", "Probing HTTP services on multi-ports...")
                prober = HTTPProber(timeout=a.timeout)
                cdn_detector = CDNDetector(timeout=a.timeout)
                tech_detector = TechDetector()
                sub_batch = subdomains[:200] if profile == "quick" else subdomains

                def probe_sub(sub):
                    hr = prober.probe(sub)
                    cr = cdn_detector.detect(sub)
                    tr = {}
                    if hr.get("alive"):
                        try:
                            import requests as req
                            from fake_useragent import UserAgent
                            ua = UserAgent()
                            p = cfg.get("settings", {}).get("proxies")
                            r = req.get(hr["url"], timeout=a.timeout, headers={"User-Agent": ua.random}, verify=False, proxies=p)
                            tr = tech_detector.detect(hr["url"], r.text, dict(r.headers))
                        except Exception:
                            pass
                    if cr.get("cdns"):
                        hr["cdn"] = cr["cdns"]
                    return sub, hr, cr, tr

                with ThreadPoolExecutor(max_workers=min(a.threads, 50)) as executor:
                    for f in as_completed([executor.submit(probe_sub, s) for s in sub_batch]):
                        try:
                            sub, hr, cr, tr = f.result()
                            http_results[sub] = hr
                            cdn_results[sub] = cr
                            if tr:
                                tech_results[sub] = tr
                        except Exception:
                            pass

                d["http"] = http_results
                d["cdn"] = cdn_results
                d["technology"] = tech_results
                alive = sum(1 for h in http_results.values() if h.get("alive"))
                self._log(f"  {alive} live hosts detected (multi-port)")
                if alive:
                    self.add_finding("info", "Web", f"{alive} live HTTP hosts found")
                self._end_module("HTTP")

        def run_ssl():
            nonlocal ssl_results
            if should_run("ssl") and not a.no_ssl:
                self._time_module("SSL")
                self._log_step("SSL", "Analyzing SSL on ALL subdomains...")
                ssl_targets = [a.domain] + [s for s in subdomains if s != a.domain]

                def check_ssl(target):
                    try:
                        sa = SSLAnalyzer(target, timeout=min(a.timeout, 4))
                        res = sa.analyze()
                        if res.get("valid"):
                            return target, res
                    except Exception:
                        pass
                    return None

                with ThreadPoolExecutor(max_workers=min(a.threads, 30)) as ex:
                    for f in as_completed([ex.submit(check_ssl, t) for t in ssl_targets]):
                        try:
                            r = f.result()
                            if r:
                                t, res = r
                                ssl_results[t] = res
                        except Exception:
                            pass
                d["ssl"] = ssl_results
                expired = sum(1 for s in ssl_results.values() if s.get("is_expired") is True)
                if expired:
                    self.add_finding("high", "SSL", f"{expired} expired SSL certificates found")
                self._log(f"  {len(ssl_results)} certificates analyzed")
                self._end_module("SSL")

        def run_ports():
            nonlocal port_results
            if not a.no_port and should_run("ports"):
                self._time_module("Ports")
                all_ips = self._get_all_ips(d)
                ps = PortScanner(timeout=1.5 if profile == "quick" else 2)
                if all_ips:
                    self._log_step("Ports", f"Scanning ~{len(all_ips)} unique IPs ({len(TIER1_PORTS)} ports)...")
                    try:
                        per_ip = ps.scan_many(all_ips)
                    except AttributeError:
                        per_ip = {}
                        for ip in all_ips:
                            r = ps.scan(ip)
                            if r:
                                per_ip[ip] = r
                    for ip, ports in per_ip.items():
                        for p in ports:
                            p["ip"] = ip
                            port_results.append(p)
                    port_results.sort(key=lambda x: x["port"])
                    d["port_scan"]["results"] = port_results
                    d["port_scan"]["per_ip"] = per_ip
                    self._log(f"  Found {len(port_results)} open ports across {len(all_ips)} IPs")
                    if port_results:
                        self.add_finding("info", "Network", f"Total {len(port_results)} open ports across all subdomains")
                    for p in port_results:
                        if p.get("port") in [21, 23, 3306, 1433, 6379, 27017, 11211]:
                            self.add_finding("high", "Network", f"Exposed service: {p['service']} (port {p['port']}) on {p.get('ip', '?')}")
                else:
                    self._log_step("Ports", "Scanning main domain ports...")
                    port_results = ps.scan(a.domain)
                    d["port_scan"]["results"] = port_results
                    self._log(f"  Found {len(port_results)} open ports")
                self._end_module("Ports")

        with ThreadPoolExecutor(max_workers=3) as ex:
            for f in as_completed([ex.submit(fn) for fn in [run_http, run_ssl, run_ports]]):
                try:
                    f.result()
                except Exception:
                    pass

        live_hosts = self._get_live_hosts(d)

        # --- ASN + Geo ---
        if should_run("asn") and not a.no_asn:
            self._time_module("ASN")
            self._log_step("ASN", "Tracing network origin...")
            asn_geo = ASNGeoLookup(timeout=a.timeout)
            first_ip = ""
            for sub_data in d.get("dns", {}).values():
                if isinstance(sub_data, dict) and sub_data.get("A"):
                    first_ip = sub_data["A"][0]
                    break
            if first_ip:
                d["asn_geo"] = asn_geo.lookup(first_ip)
                if d["asn_geo"].get("asn"):
                    self._log(f"  ASN: {d['asn_geo']['asn']} | {d['asn_geo'].get('country', '')}")
                    self.add_finding("info", "Network", f"ASN: {d['asn_geo']['asn']} | {d['asn_geo'].get('country', '')}")
                else:
                    self._log("  ASN lookup returned no data")
            else:
                self._log("  No IP found for ASN lookup")
            self._end_module("ASN")

        # --- Early export to save core results ---
        self._run_exports()

        # ========== GROUP D: Security + WAF + Takeover + DirEnum + Swagger + CICD + Docker (parallel) ==========
        def run_security():
            if should_run("security") and not a.no_security:
                self._time_module("Security")
                self._log_step("Security", "Scanning security headers on all live hosts...")
                for sub, url in live_hosts:
                    try:
                        sec = SecurityHeadersChecker(timeout=a.timeout)
                        h = sec.check(url)
                        d.setdefault("security_headers", {}).setdefault("findings", [])
                        for f in h.get("findings", []):
                            if not f.get("present"):
                                sev = f.get("rating", "medium") if f.get("rating") in ["critical", "high", "medium"] else "info"
                                self.add_finding(sev, "Web", f"Missing header on {sub}: {f['header']}")
                        cors = CORSChecker(timeout=a.timeout)
                        cors_r = cors.check(url)
                        if cors_r.get("wildcard"):
                            self.add_finding("high", "Web", f"CORS wildcard on {sub}")
                    except Exception:
                        pass
                self._log("  Security headers analyzed")
                self._end_module("Security")

        def run_waf():
            if should_run("waf") and not a.no_waf:
                self._time_module("WAF")
                self._log_step("WAF", "Detecting WAF on all live hosts...")
                try:
                    wd = WAFDetector(timeout=a.timeout)
                    for sub, url in live_hosts:
                        waf_r = wd.detect(url)
                        if waf_r.get("waf_detected"):
                            d["waf"] = waf_r
                            self._log(f"  WAF on {sub}: {waf_r['waf_name']} ({waf_r['confidence']}%)")
                            self.add_finding("info", "Web", f"WAF on {sub}: {waf_r['waf_name']}")
                            break
                    if not d.get("waf", {}).get("waf_detected"):
                        self._log("  No WAF detected")
                        d.setdefault("waf", {"waf_detected": False})
                except Exception as e:
                    self._log(f"  WAF check failed: {e}")
                    d.setdefault("waf", {"waf_detected": False})
                self._end_module("WAF")

        def run_takeover():
            if should_run("takeover") and not a.no_takeover:
                self._time_module("Takeover")
                self._log_step("Takeover", "Checking ALL subdomains for takeover...")
                tc = TakeoverChecker(timeout=a.timeout)
                takeover_results = []

                def check_sub(sub):
                    r = tc.check(sub)
                    if r.get("vulnerable"):
                        return r
                    return None

                with ThreadPoolExecutor(max_workers=min(a.threads, 30)) as ex:
                    for f in as_completed([ex.submit(check_sub, s) for s in subdomains]):
                        try:
                            r = f.result()
                            if r:
                                takeover_results.append(r)
                        except Exception:
                            pass
                d["takeover"] = takeover_results
                if takeover_results:
                    self._log(f"  {len(takeover_results)} takeover vulnerabilities!")
                    for t in takeover_results:
                        self.add_finding("critical", "Vuln", f"Subdomain takeover: {t['hostname']} ({t['service']})")
                else:
                    self._log("  No takeover vulnerabilities")
                self._end_module("Takeover")

        def run_direnum():
            if not a.no_dirb and should_run("dirb"):
                self._time_module("Directories")
                self._log_step("Directories", "Brute-forcing on all live hosts...")
                wordlist = a.dirs_wordlist if a.dirs_wordlist else None
                all_dirs = []
                for sub, url in live_hosts:
                    exec_dir = TPoolExecutor(max_workers=1)
                    try:
                        future = exec_dir.submit(self._run_dir_enum_host, d, url, wordlist)
                        dirs = future.result(timeout=45)
                        if dirs:
                            all_dirs.extend(dirs)
                    except TTimeoutError:
                        self._log(f"  Dir enum timed out on {sub}")
                    except Exception as e:
                        self._log(f"  Dir enum error on {sub}: {e}")
                    finally:
                        exec_dir.shutdown(wait=False)
                d["directory_enum"] = all_dirs
                self._log(f"  Found {len(all_dirs)} paths across all hosts")
                if all_dirs:
                    for dir_f in all_dirs[:5]:
                        url_path = dir_f.get("url", "")
                        if "admin" in url_path.lower() or ".env" in url_path or ".git" in url_path:
                            self.add_finding("high", "Web", f"Sensitive path: {url_path} (HTTP {dir_f.get('status', '?')})")
                self._end_module("Directories")

        def run_swagger():
            if should_run("swagger") and not a.no_swagger:
                self._time_module("Swagger")
                self._log_step("Swagger", "Discovering API documentation...")
                swag_ex = TPoolExecutor(max_workers=1)
                try:
                    f = swag_ex.submit(self._run_swagger, d)
                    f.result(timeout=15)
                except TTimeoutError:
                    self._log("  Swagger check timed out")
                except Exception as e:
                    self._log(f"  Swagger check failed: {e}")
                finally:
                    swag_ex.shutdown(wait=False)
                if d.get("swagger"):
                    for s in d["swagger"]:
                        self.add_finding("info", "Web", f"API docs: {s.get('url', '')}")
                if d.get("graphql") and any(g.get("introspection") for g in d["graphql"]):
                    self.add_finding("high", "Web", "GraphQL introspection enabled!")
                self._end_module("Swagger")

        def run_cicd():
            if should_run("cicd") and not a.no_cicd and profile != "stealth":
                self._time_module("CI/CD")
                self._log_step("CI/CD", "Discovering CI/CD files...")
                for scheme in ["https", "http"]:
                    try:
                        cicd = CICDDiscovery(f"{scheme}://{a.domain}", timeout=a.timeout)
                        d["cicd"] = cicd.find()
                        if d["cicd"]:
                            break
                    except Exception:
                        continue
                self._log(f"  Found {len(d.get('cicd', []))} CI/CD files")
                self._end_module("CI/CD")

        def run_docker():
            if should_run("docker") and not a.no_docker and profile != "stealth":
                self._time_module("Docker")
                self._log_step("Docker", "Scanning Docker registries...")
                docker = DockerRegistryScanner(a.domain, timeout=a.timeout)
                try:
                    d["docker_registry"] = docker.scan()
                    if d["docker_registry"].get("exposed"):
                        self._log("  Docker registry EXPOSED!")
                        self.add_finding("critical", "Cloud", "Docker registry exposed!")
                except Exception:
                    d["docker_registry"] = {}
                self._end_module("Docker")

        with ThreadPoolExecutor(max_workers=7) as ex:
            for f in as_completed([ex.submit(fn) for fn in [run_security, run_waf, run_takeover, run_direnum, run_swagger, run_cicd, run_docker]]):
                try:
                    f.result()
                except Exception:
                    pass

        # ========== GROUP E: JS + Spider + Wayback + CommonCrawl + Emails + S3 + Cloud + GitHub + CVE + CMS (parallel) ==========
        def run_js():
            if should_run("js_extract") and not a.no_js_extract:
                self._time_module("JS_Extract")
                self._log_step("JS_Extract", "Extracting JS endpoints from live hosts...")
                d["js_endpoints"] = {}
                for sub, url in live_hosts:
                    try:
                        import requests as req
                        from fake_useragent import UserAgent
                        ua = UserAgent()
                        r = req.get(url, timeout=a.timeout, headers={"User-Agent": ua.random}, verify=False)
                        extractor = JSExtractor(url, timeout=a.timeout)
                        endpoints = extractor.extract(r.text)
                        if endpoints:
                            d["js_endpoints"][sub] = endpoints
                    except Exception:
                        continue
                total_ep = sum(len(v) for v in d["js_endpoints"].values())
                self._log(f"  Extracted {total_ep} JS endpoints")
                if total_ep:
                    self.add_finding("info", "Web", f"{total_ep} JS endpoints extracted")
                self._end_module("JS_Extract")

        def run_spider():
            if should_run("spider") and not a.no_spider and profile != "stealth":
                self._time_module("Spider")
                self._log_step("Spider", "Crawling for links...")
                for sub, url in live_hosts[:5]:
                    try:
                        spider = LinkSpider(url, timeout=a.timeout, max_pages=20 if profile == "quick" else 50)
                        links = spider.crawl(max_workers=10)
                        if links:
                            d.setdefault("spider_links", {})[sub] = links
                    except Exception:
                        continue
                total_links = sum(len(v) for v in d.get("spider_links", {}).values())
                self._log(f"  Crawled {total_links} links")
                self._end_module("Spider")

        def run_wayback():
            if should_run("wayback") and not a.no_wayback:
                self._time_module("Wayback")
                self._log_step("Wayback", "Mining web archives...")
                wayback = WaybackScraper(a.domain, timeout=a.timeout)
                try:
                    d["wayback_urls"] = wayback.scrape()
                except Exception:
                    d["wayback_urls"] = []
                self._log(f"  Wayback: {len(d['wayback_urls'])} URLs")
                self._end_module("Wayback")

        def run_commoncrawl():
            if should_run("commoncrawl") and not a.no_commoncrawl:
                self._time_module("CommonCrawl")
                self._log_step("CommonCrawl", "Mining CommonCrawl index...")
                cc = CommonCrawlScraper(a.domain, timeout=a.timeout)
                try:
                    d["commoncrawl_urls"] = cc.scrape()
                except Exception:
                    d["commoncrawl_urls"] = []
                self._log(f"  CommonCrawl: {len(d['commoncrawl_urls'])} URLs")
                self._end_module("CommonCrawl")

        def run_emails():
            if should_run("emails") and not a.no_emails:
                self._time_module("Emails")
                self._log_step("Emails", "Harvesting email addresses...")
                harvester = EmailHarvester(a.domain, timeout=a.timeout)
                d["emails"] = harvester.harvest()
                if d["emails"]:
                    self._log(f"  Found {len(d['emails'])} emails")
                    self.add_finding("info", "Web", f"{len(d['emails'])} email addresses found")
                self._end_module("Emails")

        def run_s3():
            if should_run("s3") and not a.no_s3:
                self._time_module("S3")
                self._log_step("S3", "Scanning AWS S3 buckets...")
                s3 = S3Scanner(timeout=a.timeout)
                try:
                    d["s3"] = s3.scan(a.domain)
                    if d["s3"]:
                        for b in d["s3"]:
                            if b.get("accessible"):
                                self.add_finding("high", "Cloud", f"S3 bucket accessible: {b.get('url', '')}")
                except Exception:
                    d["s3"] = []
                self._log("  S3 scan complete")
                self._end_module("S3")

        def run_cloud():
            if should_run("cloud") and not a.no_cloud and profile != "stealth":
                self._time_module("Cloud")
                self._log_step("Cloud", "Scanning GCP and Azure storage...")
                cloud = CloudScanner(a.domain, timeout=min(a.timeout, 5))
                d["cloud_storage"] = cloud.scan_all()
                gcp = len(d["cloud_storage"].get("gcp", []))
                azure = len(d["cloud_storage"].get("azure", []))
                self._log(f"  GCP: {gcp} buckets, Azure: {azure} containers")
                self._end_module("Cloud")

        def run_github():
            if should_run("github") and not a.no_github:
                self._time_module("GitHub")
                self._log_step("GitHub", "Searching GitHub for leaks...")
                gh_token = cfg.get("api_keys", {}).get("github_token", "")
                gh = GitHubRecon(token=gh_token, timeout=a.timeout)
                try:
                    d["github"] = gh.search(a.domain)
                    self._log("  GitHub recon complete")
                except Exception as e:
                    self._log(f"  GitHub recon failed: {e}")
                    d["github"] = {}
                self._end_module("GitHub")

        def run_cve():
            if should_run("cve") and not a.no_cve:
                self._time_module("CVE")
                self._log_step("CVE", "Matching CVEs to detected technologies...")
                try:
                    cve_checker = CVEChecker()
                    if d.get("technology"):
                        d["cve"] = cve_checker.check(d["technology"])
                    if d.get("cve"):
                        self.add_finding("info", "Vuln", f"{len(d['cve'])} potential CVEs matched")
                        for c in d["cve"]:
                            self.add_finding("medium", "Vuln", f"{c['technology']} {c.get('version', '?')}: {', '.join(c['cves'][:3])}")
                except Exception as e:
                    self._log(f"  CVE check failed: {e}")
                self._log("  CVE matching complete")
                self._end_module("CVE")

        def run_cms():
            if should_run("cms") and not a.no_cms:
                self._time_module("CMS")
                self._log_step("CMS", "Detecting CMS on live hosts (50+ fingerprints)...")
                for sub, url in live_hosts[:3]:
                    cms_scanner = CMSScanner(url, timeout=min(a.timeout, 5))
                    try:
                        d["cms"] = cms_scanner.scan(global_timeout=30)
                        detected = [k for k, v in d["cms"].items() if v.get("detected")]
                        if detected:
                            self._log(f"  CMS on {sub}: {', '.join(detected)}")
                            for c in detected:
                                self.add_finding("info", "Web", f"CMS on {sub}: {c}")
                            break
                    except Exception:
                        continue
                if not d.get("cms"):
                    self._log("  No CMS detected")
                self._end_module("CMS")

        with ThreadPoolExecutor(max_workers=10) as ex:
            for f in as_completed([ex.submit(fn) for fn in [run_js, run_spider, run_wayback, run_commoncrawl, run_emails, run_s3, run_cloud, run_github, run_cve, run_cms]]):
                try:
                    f.result()
                except Exception:
                    pass

        # ========== BASIC VULN SCAN ==========
        if should_run("vuln") and not a.no_vuln and profile != "stealth":
            self._time_module("Vuln")
            self._log_step("Vuln", "Basic vulnerability checks on live hosts...")
            for sub, url in live_hosts:
                try:
                    import requests as req
                    from fake_useragent import UserAgent
                    ua = UserAgent()
                    hdrs = {"User-Agent": ua.random}

                    sqli_url = url + ("?" if "?" not in url else "&") + "id=1' OR '1'='1"
                    try:
                        r = req.get(sqli_url, timeout=a.timeout, headers=hdrs, verify=False)
                        if any(w in r.text.lower() for w in ["sql", "mysql", "syntax", "odbc"]):
                            self.add_finding("high", "Vuln", f"Possible SQLi reflection on {sub}")
                    except Exception:
                        pass

                    xss_url = url + ("?" if "?" not in url else "&") + "q=<script>alert(1)</script>"
                    try:
                        r = req.get(xss_url, timeout=a.timeout, headers=hdrs, verify=False)
                        if "<script>alert(1)</script>" in r.text:
                            self.add_finding("critical", "Vuln", f"Reflected XSS on {sub}")
                    except Exception:
                        pass

                    redir_url = url + ("?" if "?" not in url else "&") + "url=https://evil.com"
                    try:
                        r = req.get(redir_url, timeout=a.timeout, headers=hdrs, verify=False, allow_redirects=False)
                        if r.status_code in [301, 302, 303, 307] and "evil.com" in r.headers.get("Location", ""):
                            self.add_finding("high", "Vuln", f"Open redirect on {sub}")
                    except Exception:
                        pass

                    env_url = url.rstrip("/") + "/.env"
                    try:
                        r = req.get(env_url, timeout=min(a.timeout, 3), headers=hdrs, verify=False)
                        if r.status_code == 200 and any(w in r.text for w in ["DB_", "APP_", "SECRET", "PASSWORD"]):
                            self.add_finding("critical", "Vuln", f".env file exposed on {sub}")
                    except Exception:
                        pass
                except Exception:
                    continue
            self._end_module("Vuln")

        # ========== GROUP F: Favicon + Screenshots + Graph (parallel) ==========
        def run_favicon():
            if should_run("favicon") and not a.no_favicon:
                self._time_module("Favicon")
                self._log_step("Favicon", "Calculating hashes on all live hosts...")
                fav = FaviconHash(timeout=a.timeout)
                for sub, url in live_hosts:
                    try:
                        fr = fav.get_favicon_hash(url)
                        if fr and fr.get("size", 0) > 100:
                            d["favicon"] = fr
                            self._log(f"  Hash for {sub}: {fr.get('mmh3', 'N/A')}")
                            break
                    except Exception:
                        continue
                if not d.get("favicon"):
                    for host in [a.domain, f"www.{a.domain}"]:
                        for scheme in ["https", "http"]:
                            try:
                                fr = fav.get_favicon_hash(f"{scheme}://{host}")
                                if fr and fr.get("size", 0) > 100:
                                    d["favicon"] = fr
                                    break
                            except Exception:
                                continue
                        if d.get("favicon"):
                            break
                if d.get("favicon"):
                    self._log(f"  Favicon hash: {d['favicon'].get('mmh3', 'N/A')}")
                self._end_module("Favicon")

        def run_screenshots():
            if not a.no_screenshot and should_run("screenshot"):
                self._time_module("Screenshots")
                try:
                    st = ScreenshotTaker(output_dir=f"screenshots_{a.domain}")
                    live_urls = [url for _, url in live_hosts]
                    if live_urls:
                        d["screenshots"] = st.take_many(live_urls)
                        self._log(f"  Screenshots taken: {len(d['screenshots'])}")
                except Exception:
                    pass
                self._end_module("Screenshots")

        def run_graph():
            if not a.no_graph and should_run("graph"):
                self._time_module("Graph")
                self._log_step("Graph", "Generating network graph...")
                try:
                    gg = GraphVizGenerator()
                    gd = gg.generate_d3_json(d)
                    d["graph"] = gd
                    gh = gg.generate_html(gd, f"XREFS0 - {a.domain}")
                    with open(f"graph_{a.domain}.html", "w", encoding="utf-8") as f:
                        f.write(gh)
                    self._log(f"  Graph: graph_{a.domain}.html")
                except Exception as e:
                    self._log(f"  Graph skipped: {e}")
                self._end_module("Graph")

        with ThreadPoolExecutor(max_workers=3) as ex:
            for f in as_completed([ex.submit(fn) for fn in [run_favicon, run_screenshots, run_graph]]):
                try:
                    f.result()
                except Exception:
                    pass

        if self.history and self.scan_id and not self.args.no_history:
            elapsed = int(time.time() - self.start_time) if self.start_time else 0
            self.history.save_scan(self.args.domain, elapsed, list(self.module_times.keys()), d)

    def _show_results(self):
        d = self.data
        if not self.args.quiet:
            if console and HAS_RICH:
                console.print(f"\n  [dark_red]{'='*50}[/]")
                console.print(f"  [bold red]FINDINGS SUMMARY[/]")
                console.print(f"  [dark_red]{'='*50}[/]\n")
            else:
                self._log("=" * 50)
                self._log("FINDINGS SUMMARY")
                self._log("=" * 50)

        self._print_findings()

        output = OutputEngine(d, self._findings)
        output.print_summary()
        output.print_whois(d["whois"])
        output.print_real_ip(d["real_ip"])
        output.print_subdomains_table(d.get("subdomains", []), d.get("dns"), d.get("http"))
        if d.get("port_scan", {}).get("results"):
            output.print_port_scan(d["port_scan"]["results"])
        if d.get("mail_security"):
            output.print_mail_security(d["mail_security"])
        if d.get("security_headers", {}).get("findings"):
            output.print_security_headers(d["security_headers"])
        if d.get("takeover"):
            output.print_takeover(d["takeover"])
        if d.get("cve"):
            output.print_cve(d["cve"])
        if d.get("emails"):
            output.print_emails(d["emails"])
        output.print_cloud_results(d.get("cloud_storage", {}))
        output.print_cms_results(d.get("cms", {}))
        output.print_waf_results(d.get("waf", {}))
        output.print_cicd_results(d.get("cicd", []))
        output.print_swagger_results(d.get("swagger", []), d.get("graphql", []))
        output.print_docker_results(d.get("docker_registry", {}))

        if self.args.json:
            output.export_json(self.args.json)
        if self.args.yaml:
            output.export_yaml(self.args.yaml)
        if self.args.csv:
            output.export_csv(self.args.csv)
        if self.args.xlsx:
            output.export_xlsx(self.args.xlsx)
        if self.args.html:
            output.export_html(self.args.html)
        if self.args.markdown:
            output.export_markdown(self.args.markdown)
        if self.args.pdf:
            output.export_pdf(self.args.pdf)

    def _show_final_report(self):
        d = self.data
        elapsed = int(time.time() - self.start_time) if self.start_time else 0
        mins, secs = divmod(elapsed, 60)

        subdomain_count = len(d.get("subdomains", []))
        http_alive = sum(1 for h in d.get("http", {}).values() if h.get("alive"))
        ports_open = len(d.get("port_scan", {}).get("results", []))
        email_count = len(d.get("emails", []))
        takeover_count = len(d.get("takeover", []))
        s3_count = len(d.get("s3", []))
        dir_count = len(d.get("directory_enum", []))
        wayback_count = len(d.get("wayback_urls", []))
        tech_count = len(d.get("technology", {}))
        vuln_count = len(d.get("cve", []))
        crit_findings = len([f for f in self._findings if f["severity"] == "critical"])
        high_findings = len([f for f in self._findings if f["severity"] == "high"])

        if not self.args.quiet:
            if console and HAS_RICH:
                report_table = Table.grid(padding=(0, 2))
                report_table.add_column(style="white", justify="right")
                report_table.add_column(style="bold white")
                report_table.add_row("Target:", f"[bold yellow]{self.args.domain}[/]")
                report_table.add_row("Elapsed:", f"[cyan]{mins}m {secs}s[/]")
                report_table.add_row("Subdomains:", f"{subdomain_count}")
                report_table.add_row("Live Hosts:", f"{http_alive}")
                report_table.add_row("Open Ports:", f"{ports_open}")
                report_table.add_row("Emails:", f"{email_count}")
                report_table.add_row("Takeovers:", f"{takeover_count}")
                report_table.add_row("S3 Buckets:", f"{s3_count}")
                report_table.add_row("Directories:", f"{dir_count}")
                report_table.add_row("Wayback URLs:", f"{wayback_count}")
                report_table.add_row("Tech Stacks:", f"{tech_count}")
                report_table.add_row("CVE Matches:", f"{vuln_count}")
                report_table.add_row("", "")
                report_table.add_row("CRITICAL:", f"[bold red]{crit_findings}[/]")
                report_table.add_row("HIGH:", f"[yellow]{high_findings}[/]")

                panel = Panel(
                    report_table,
                    border_style="dark_red",
                    box=DOUBLE_EDGE,
                    title="[bold red]ANALYSIS COMPLETE[/]",
                    title_align="center",
                    subtitle=f"[italic dark_red]\"{rnd_quote()}\"[/]",
                    subtitle_align="center",
                    padding=(1, 2),
                )
                console.print()
                console.print(panel)
                console.print(f"\n  [dim]Coded by MASA[/]")
            else:
                report = f"""
  +----------------------------------------------+
  | XREFS0 - MISSION COMPLETE                    |
  +----------------------------------------------+
  | Target:      {self.args.domain:39s} |
  | Elapsed:     {mins}m {secs}s                                            |
  | Subdomains:  {subdomain_count}                                          |
  | Live Hosts:  {http_alive}                                          |
  | Open Ports:  {ports_open}                                          |
  | Emails:      {email_count}                                          |
  | Takeovers:   {takeover_count}                                          |
  | S3 Buckets:  {s3_count}                                          |
  | Directories: {dir_count}                                          |
  | Wayback URLs:{wayback_count}                                          |
  | Tech Stacks: {tech_count}                                          |
  | CVE Matches: {vuln_count}                                          |
  | CRITICAL:    {crit_findings}                                          |
  | HIGH:        {high_findings}                                          |
  | Status:      SCAN COMPLETE                                         |
  +----------------------------------------------+
  | Coded by MASA                                                   |
  +----------------------------------------------+
"""
                print(report)

    def _write_log(self, filepath):
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(f"XREFS0 Scan Log - {self.args.domain}\n")
                f.write(f"Time: {datetime.now().isoformat()}\n")
                f.write(f"Duration: {int(time.time() - self.start_time)}s\n")
                f.write(f"Subdomains: {len(self.data.get('subdomains', []))}\n")
                f.write(f"Modules: {', '.join(self.module_times.keys())}\n")
                f.write(f"Critical: {len([x for x in self._findings if x['severity'] == 'critical'])}\n")
                f.write(f"High: {len([x for x in self._findings if x['severity'] == 'high'])}\n")
            self._log(f"  Log saved to: {filepath}")
        except Exception:
            pass

    def show_help(self, parser):
        help_text = f"""
XREFS0 - Cyber Intelligence & Domain Recon Platform
Coded by: MASA

USAGE:
  xrefs0 <domain> [options]

TARGET:
  domain                  Target domain or URL to scan

OUTPUT:
  --html FILE             Export HTML report
  --json FILE             Export JSON data
  --yaml, -y FILE         Export YAML data
  --csv FILE              Export CSV data
  --xlsx FILE             Export XLSX spreadsheet
  --pdf FILE              Export PDF report
  --markdown, -md FILE    Export Markdown report

SCAN CONTROLS:
  --config, -c FILE       API keys config file (default: config.yaml)
  --threads, -T NUM       Thread count (default: 50)
  --timeout, -t SEC       Request timeout in seconds (default: 10)
  --max-subdomains, -m    Max subdomains to check (0 = all)
  --profile, -p MODE      Scan profile: quick, full, stealth (default: full)
  --delay, -d SEC         Delay between requests
  --rate-limit, -rl NUM   Max requests per second
  --proxy URL             Proxy URL (e.g. socks5://127.0.0.1:9050)
  --retry NUM             Retry attempts on failure (default: 2)
  --resolvers IPs         Custom DNS resolvers (default: 1.1.1.1 8.8.8.8)
  --resume                Resume last scan for this domain
  --silent, -s            Silent mode (no animations)
  --quiet, -q             Quiet mode (minimal output)
  --compact               Compact output mode
  --log, -l FILE          Log file output
  --dirs-wordlist FILE    Custom directory wordlist path
  --subs-wordlist FILE    Custom subdomain wordlist path
  --only-modules MODULES  Run only specified modules (space separated)

DISABLE MODULES:
  --no-http               --no-port          --no-dirb          --no-screenshot
  --no-graph              --no-dns-brute     --no-js-extract    --no-spider
  --no-waf                --no-cloud         --no-swagger       --no-cicd
  --no-cms                --no-docker        --no-reverse-dns   --no-history
  --no-wayback            --no-commoncrawl   --no-dorks         --no-github
  --no-cve                --no-whois         --no-subdomains    --no-dns
  --no-real-ip            --no-ssl           --no-mail          --no-security
  --no-asn                --no-takeover      --no-s3            --no-emails
  --no-favicon            --no-vuln

BATCH/CIDR:
  --file, -f FILE         File containing domains to scan (one per line)
  --cidr CIDRS            CIDR ranges to scan (e.g. 192.168.1.0/24)

MODULES:
  whois, subdomains, dns, dns_bruteforce, reverse_dns, real_ip, http,
  js_extract, spider, ssl, mail, security, waf, ports, asn, takeover,
  s3, cloud, emails, wayback, commoncrawl, dorks, github, cve, cms,
  dirb, swagger, cicd, docker, favicon, screenshot, graph, vuln

EXAMPLES:
  xrefs0 example.com
  xrefs0 example.com --html report.html --json data.json
  xrefs0 example.com -T 100 -t 30
  xrefs0 example.com --profile stealth --proxy socks5://127.0.0.1:9050
  xrefs0 example.com --only-modules whois subdomains dns
  xrefs0 example.com --rate-limit 10 --delay 0.5
  xrefs0 --file domains.txt --html report_DOMAIN.html
  xrefs0 example.com --cidr 192.168.1.0/24

Coded by MASA | XREFS0 v2.0
"""
        print(help_text)

    def show_version(self):
        print("XREFS0 v2.0 - Cyber Intelligence & Domain Recon Platform")
        print("Coded by MASA")
        print("Protocol: Dark Recon")
        print("Modules: 38 | Ports: 1000 | CMS: 50+ | Takeover: 90+")

    def _run_exports(self):
        try:
            output = OutputEngine(self.data, self._findings)
            if self.args.json:
                output.export_json(self.args.json)
            if self.args.yaml:
                output.export_yaml(self.args.yaml)
            if self.args.csv:
                output.export_csv(self.args.csv)
            if self.args.xlsx:
                output.export_xlsx(self.args.xlsx)
            if self.args.html:
                output.export_html(self.args.html)
            if self.args.markdown:
                output.export_markdown(self.args.markdown)
            if self.args.pdf:
                output.export_pdf(self.args.pdf)
        except Exception as e:
            self._log(f"  Export error: {e}")

    def _load_config(self, config_path):
        config = {}
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    config = yaml.safe_load(f) or {}
            except Exception:
                pass
        return config

    def _run_dir_enum_host(self, d, base_url, wordlist=None):
        a = self.args
        dir_enum = DirEnumerator(base_url, timeout=min(a.timeout, 5))
        try:
            if wordlist:
                with open(wordlist, "r") as f:
                    paths = [line.strip() for line in f if line.strip()]
                return dir_enum.enumerate(paths=paths, max_workers=a.threads)
            return dir_enum.enumerate(max_workers=min(a.threads, 30))
        except Exception:
            return []

    def _run_swagger(self, d):
        a = self.args
        for scheme in ["https", "http"]:
            try:
                from modules.swagger_finder import SwaggerFinder
                sf = SwaggerFinder(f"{scheme}://{a.domain}", timeout=min(a.timeout, 5))
                d["swagger"] = sf.find_swagger()
                d["graphql"] = sf.check_graphql_introspection()
                if d["swagger"] or d["graphql"]:
                    break
            except Exception:
                continue
        if d.get("swagger"):
            self._log(f"  Found {len(d['swagger'])} API docs")
        if d.get("graphql"):
            self._log(f"  Found {len(d['graphql'])} GraphQL endpoints")
        if not d.get("swagger") and not d.get("graphql"):
            self._log("  No API documentation found")

    def _init_data(self):
        return {
            "domain": self.args.domain,
            "timestamp": datetime.now().isoformat(),
            "subdomains": [],
            "dns": {},
            "real_ip": {},
            "whois": {},
            "http": {},
            "technology": {},
            "cdn": {},
            "ssl": {},
            "security_headers": {},
            "cookies": {},
            "cors": {},
            "mail_security": {},
            "takeover": [],
            "s3": [],
            "port_scan": {"results": []},
            "asn_geo": {},
            "emails": [],
            "google_dorks": [],
            "github": {},
            "wayback_urls": [],
            "commoncrawl_urls": [],
            "directory_enum": [],
            "cve": [],
            "favicon": {},
            "graph": {},
            "waf": {},
            "cloud_storage": {},
            "cms": {},
            "swagger": [],
            "graphql": [],
            "cicd": [],
            "docker_registry": {},
            "reverse_dns": {},
            "js_endpoints": {},
            "spider_links": {},
        }

if __name__ == "__main__":
    try:
        app = XREFS0()
        app.run()
    except KeyboardInterrupt:
        if console and HAS_RICH:
            console.print(f"\n\n  [italic dark_red]\"You cannot escape what you have already awakened.\"[/]")
            console.print(f"  [bold red]XREFS0 INTERRUPTED BY OPERATOR[/]")
        else:
            print(f"\n\n  \"You cannot escape what you have already awakened.\"")
            print(f"  XREFS0 INTERRUPTED BY OPERATOR")
        sys.exit(1)
    except Exception as e:
        print(f"\n  CRITICAL ERROR: {e}")
        sys.exit(1)
