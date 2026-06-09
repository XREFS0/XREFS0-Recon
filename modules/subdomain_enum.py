import requests
import json
import re
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from fake_useragent import UserAgent
import tldextract

ua = UserAgent()

# API response cache: key = source_name + domain, value = set of subdomains
_api_cache = {}

def _cached_fetch(source_name, domain, fetch_func):
    key = f"{source_name}:{domain}"
    if key in _api_cache:
        return _api_cache[key]
    result = fetch_func()
    _api_cache[key] = result
    return result

class SubdomainEnumerator:
    def __init__(self, domain, config=None):
        self.domain = domain
        self.config = config or {}
        self.subdomains = set()
        self.ext = tldextract.TLDExtract()
        self.timeout = 10

    def enumerate_all(self):
        sources = [
            ("crt.sh", self._crt_sh),
            ("alienvault", self._alienvault_otx),
            ("hackertarget", self._hackertarget),
            ("dnsdumpster", self._dnsdumpster),
            ("rapiddns", self._rapiddns),
            ("riddler", self._riddler),
            ("omnisint", self._omnisint),
            ("jldc", self._jldc),
        ]
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(lambda s=name, fn=func: (s, _cached_fetch(s, self.domain, fn))): None for name, func in sources}
            for f in as_completed(futures):
                try:
                    name, result = f.result()
                    if result:
                        before = len(self.subdomains)
                        self.subdomains.update(result)
                        added = len(self.subdomains) - before
                    else:
                        pass
                except Exception:
                    pass
        return sorted(self.subdomains)

    def _crt_sh(self):
        subs = set()
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random})
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for n in name.split("\n"):
                        n = n.strip().lower()
                        if n and n.endswith(self.domain) and "*" not in n:
                            subs.add(n)
        except Exception:
            pass
        return subs

    def _alienvault_otx(self):
        subs = set()
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random})
            if r.status_code == 200:
                data = r.json()
                for entry in data.get("passive_dns", []):
                    host = entry.get("hostname", "").strip().lower()
                    if host and host.endswith(self.domain):
                        subs.add(host)
        except Exception:
            pass
        return subs

    def _hackertarget(self):
        subs = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random})
            if r.status_code == 200:
                for line in r.text.strip().split("\n"):
                    parts = line.split(",")
                    if len(parts) >= 1:
                        host = parts[0].strip().lower()
                        if host and host.endswith(self.domain):
                            subs.add(host)
        except Exception:
            pass
        return subs

    def _dnsdumpster(self):
        subs = set()
        try:
            session = requests.Session()
            r1 = session.get("https://dnsdumpster.com/", timeout=self.timeout)
            if "csrfmiddlewaretoken" in r1.text:
                csrf = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', r1.text)
                if csrf:
                    token = csrf.group(1)
                    data = {"csrfmiddlewaretoken": token, "targetip": self.domain, "user": "free"}
                    headers = {"Referer": "https://dnsdumpster.com/", "User-Agent": ua.random}
                    r2 = session.post("https://dnsdumpster.com/", data=data, headers=headers, timeout=self.timeout)
                    if "host" in r2.text.lower():
                        found = re.findall(r'<td class="col-md-4">([^<]+)</td>', r2.text)
                        for host in found:
                            host = host.strip().lower()
                            if host.endswith(self.domain):
                                subs.add(host)
        except Exception:
            pass
        return subs

    def _rapiddns(self):
        subs = set()
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
            r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random})
            if r.status_code == 200:
                found = re.findall(r'<td>([^<]+\.' + re.escape(self.domain) + r')</td>', r.text)
                for host in found:
                    subs.add(host.strip().lower())
        except Exception:
            pass
        return subs

    def _riddler(self):
        subs = set()
        try:
            url = f"https://riddler.io/search/exportcsv?q=host:{self.domain}"
            r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random})
            if r.status_code == 200:
                for line in r.text.strip().split("\n"):
                    parts = line.split(",")
                    if len(parts) >= 1:
                        host = parts[0].strip('"').strip().lower()
                        if host and host.endswith(self.domain):
                            subs.add(host)
        except Exception:
            pass
        return subs

    def _omnisint(self):
        subs = set()
        try:
            url = f"https://omnisint.io/subdomains/{self.domain}"
            r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random})
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list):
                    for entry in data:
                        host = entry.get("hostname", "").strip().lower() if isinstance(entry, dict) else str(entry).strip().lower()
                        if host and host.endswith(self.domain):
                            subs.add(host)
        except Exception:
            pass
        return subs

    def _jldc(self):
        subs = set()
        try:
            url = f"https://jldc.me/api/subdomains?domain={self.domain}"
            r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random})
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, dict):
                    for entry in data.get("subdomains", []):
                        host = entry.strip().lower() if isinstance(entry, str) else entry.get("hostname", "").strip().lower()
                        if host and host.endswith(self.domain):
                            subs.add(host)
        except Exception:
            pass
        return subs
