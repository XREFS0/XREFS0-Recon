import requests
from fake_useragent import UserAgent

ua = UserAgent()

class WaybackScraper:
    def __init__(self, domain, timeout=10):
        self.domain = domain
        self.timeout = timeout

    def scrape(self):
        urls = set()
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}&output=json&fl=original,timestamp,statuscode&collapse=urlkey&limit=1000"
            r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random})
            if r.status_code == 200:
                data = r.json()
                for entry in data[1:]:
                    if len(entry) >= 1:
                        urls.add(entry[0])
        except Exception:
            pass
        return sorted(urls)

    def scrape_unique_domains(self):
        domains = set()
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}&output=json&fl=original&collapse=urlkey&limit=5000"
            r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random})
            if r.status_code == 200:
                data = r.json()
                for entry in data[1:]:
                    if len(entry) >= 1:
                        from urllib.parse import urlparse
                        parsed = urlparse(entry[0])
                        host = parsed.netloc or parsed.path
                        if host and self.domain in host:
                            domains.add(host)
        except Exception:
            pass
        return sorted(domains)
