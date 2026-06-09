import dns.resolver
import socket
import requests
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from fake_useragent import UserAgent

ua = UserAgent()

class RealIPFinder:
    def __init__(self, domain, timeout=10):
        self.domain = domain
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def find(self, subdomains=None):
        ips = set()
        methods = {}

        mx_ips = self._from_mx_records()
        if mx_ips:
            ips.update(mx_ips)
            methods["mx_records"] = list(mx_ips)

        ns_ips = self._from_ns_records()
        if ns_ips:
            ips.update(ns_ips)
            methods["ns_records"] = list(ns_ips)

        soa_ips = self._from_soa_records()
        if soa_ips:
            ips.update(soa_ips)
            methods["soa_record"] = list(soa_ips)

        sub_ips = self._from_subdomains(subdomains)
        if sub_ips:
            ips.update(sub_ips)
            methods["subdomain_resolution"] = list(sub_ips)

        hist_ips = self._from_historical_dns()
        if hist_ips:
            ips.update(hist_ips)
            methods["historical_dns"] = list(hist_ips)

        cert_ips = self._from_ssl_certificates()
        if cert_ips:
            ips.update(cert_ips)
            methods["ssl_certificates"] = list(cert_ips)

        return {"ips": list(ips), "methods": methods}

    def _from_mx_records(self):
        ips = set()
        try:
            answers = self.resolver.resolve(self.domain, "MX", lifetime=self.timeout)
            for r in answers:
                mx_host = str(r.exchange).rstrip(".")
                try:
                    ip = socket.gethostbyname(mx_host)
                    ips.add(ip)
                except Exception:
                    continue
        except Exception:
            pass
        return ips

    def _from_ns_records(self):
        ips = set()
        try:
            answers = self.resolver.resolve(self.domain, "NS", lifetime=self.timeout)
            for r in answers:
                ns_host = str(r).rstrip(".")
                try:
                    ip = socket.gethostbyname(ns_host)
                    ips.add(ip)
                except Exception:
                    continue
        except Exception:
            pass
        return ips

    def _from_soa_records(self):
        ips = set()
        try:
            answers = self.resolver.resolve(self.domain, "SOA", lifetime=self.timeout)
            soa_host = str(answers[0].mname).rstrip(".")
            try:
                ip = socket.gethostbyname(soa_host)
                ips.add(ip)
            except Exception:
                pass
        except Exception:
            pass
        return ips

    def _from_subdomains(self, subdomains):
        ips = set()
        if not subdomains:
            return ips
        def check_sub(sub):
            try:
                ip = socket.gethostbyname(sub)
                return ip
            except Exception:
                return None
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = [executor.submit(check_sub, s) for s in subdomains[:50]]
            for f in as_completed(futures):
                ip = f.result()
                if ip:
                    ips.add(ip)
        return ips

    def _from_historical_dns(self):
        ips = set()
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random})
            if r.status_code == 200:
                data = r.json()
                ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
                for entry in data:
                    val = str(entry.get("name_value", ""))
                    ips.update(ip_pattern.findall(val))
        except Exception:
            pass
        return ips

    def _from_ssl_certificates(self):
        ips = set()
        try:
            url = f"https://search.censys.io/api/v1/certificates?q={self.domain}"
            headers = {"User-Agent": ua.random}
            r = requests.get(url, headers=headers, timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                for cert in data.get("results", []):
                    for ip in cert.get("parsed", {}).get("subject_alt_names", {}).get("dns_names", []):
                        if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                            ips.add(ip)
        except Exception:
            pass
        return ips
