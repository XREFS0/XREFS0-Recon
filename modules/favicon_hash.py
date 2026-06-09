import requests
import hashlib
from fake_useragent import UserAgent
import re
from urllib.parse import urljoin

ua = UserAgent()

class FaviconHash:
    def __init__(self, timeout=10):
        self.timeout = timeout

    def get_favicon_hash(self, url):
        try:
            html = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random}, verify=False).text
            match = re.search(r'<link[^>]*rel=["\'](?:shortcut )?icon["\'][^>]*href=["\']([^"\']+)["\']', html, re.IGNORECASE)
            if not match:
                match = re.search(r'<link[^>]*href=["\']([^"\']+)["\'][^>]*rel=["\'](?:shortcut )?icon["\']', html, re.IGNORECASE)
            if not match:
                favicon_url = urljoin(url, "/favicon.ico")
            else:
                favicon_url = urljoin(url, match.group(1))
            r = requests.get(favicon_url, timeout=self.timeout, headers={"User-Agent": ua.random}, verify=False)
            if r.status_code == 200:
                mmh3 = self._mmh3_hash(r.content)
                md5 = hashlib.md5(r.content).hexdigest()
                sha256 = hashlib.sha256(r.content).hexdigest()
                return {
                    "url": favicon_url,
                    "mmh3": mmh3,
                    "md5": md5,
                    "sha256": sha256,
                    "size": len(r.content),
                }
        except Exception:
            pass
        return None

    def _mmh3_hash(self, data):
        try:
            import mmh3
            import base64
            b64 = base64.b64encode(data)
            return mmh3.hash(b64)
        except ImportError:
            return None
