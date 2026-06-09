import re
import requests
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from fake_useragent import UserAgent

ua = UserAgent()

ENDPOINT_PATTERNS = [
    r'["\']([a-zA-Z0-9_\-/]{2,60}\.(js|json|xml|txt|html|php|aspx|jsp|do|action|api|sql|bak|cfg|conf))["\']',
    r'(?:api|rest|v1|v2|v3|graphql|swagger|docs)[a-zA-Z0-9_\-/]*',
    r'(?:get|post|put|delete|patch|fetch|ajax|axios|request)\s*\(?\s*["\']([a-zA-Z0-9_\-/]{2,})["\']',
    r'url\s*[:=]\s*["\']([a-zA-Z0-9_\-/]{2,})["\']',
    r'(?:href|src|action)\s*=\s*["\']([a-zA-Z0-9_\-/]{2,})["\']',
    r'["\']([a-zA-Z0-9_\-/]{2,}\.(php|aspx|jsp|do|action))["\']',
    r'(?:endpoint|route|path|uri)\s*[:=]\s*["\']([a-zA-Z0-9_\-/]{2,})["\']',
]

class JSExtractor:
    def __init__(self, base_url, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.domain = urlparse(base_url).netloc

    def extract(self, html, max_workers=20):
        js_urls = self._find_js_urls(html)
        if not js_urls:
            return []
        all_endpoints = set()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self._fetch_and_parse, js): js for js in js_urls}
            for f in as_completed(futures):
                try:
                    endpoints = f.result()
                    if endpoints:
                        all_endpoints.update(endpoints)
                except Exception:
                    pass
        return sorted(all_endpoints)

    def _find_js_urls(self, html):
        urls = set()
        patterns = [
            r'<script[^>]*src=[\'"]([^\'"]+)[\'"]',
            r'(?:require|import)\s*\(?\s*[\'"]([^\'"]+\.js)[\'"]',
        ]
        for pattern in patterns:
            for m in re.finditer(pattern, html, re.IGNORECASE):
                js_url = m.group(1)
                full_url = urljoin(self.base_url, js_url)
                if self.domain in urlparse(full_url).netloc:
                    urls.add(full_url)
        return list(urls)

    def _fetch_and_parse(self, js_url):
        try:
            r = requests.get(js_url, timeout=self.timeout, headers={"User-Agent": ua.random}, verify=False)
            if r.status_code != 200:
                return []
            return self._parse_js(r.text)
        except Exception:
            return []

    def _parse_js(self, content):
        endpoints = set()
        for pattern in ENDPOINT_PATTERNS:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                ep = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                try:
                    full_url = urljoin(self.base_url, ep)
                    if self.domain in urlparse(full_url).netloc:
                        endpoints.add(full_url)
                except Exception:
                    pass
        return endpoints
