import re
import requests
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from fake_useragent import UserAgent

ua = UserAgent()

class LinkSpider:
    def __init__(self, base_url, timeout=10, max_pages=50):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_pages = max_pages
        self.domain = urlparse(base_url).netloc
        self.visited = set()
        self.links = set()

    def crawl(self, max_workers=10):
        self._crawl_page(self.base_url)
        urls_to_crawl = [self.base_url]
        while urls_to_crawl and len(self.visited) < self.max_pages:
            batch = urls_to_crawl[:max_workers]
            urls_to_crawl = urls_to_crawl[max_workers:]
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(self._crawl_page, url): url for url in batch}
                for f in as_completed(futures):
                    try:
                        new_links = f.result()
                        if new_links:
                            for link in new_links:
                                if link not in self.visited and link not in urls_to_crawl:
                                    urls_to_crawl.append(link)
                    except Exception:
                        pass
        return sorted(self.links)

    def _crawl_page(self, url):
        if url in self.visited:
            return []
        self.visited.add(url)
        found = []
        try:
            r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random}, verify=False, allow_redirects=True)
            if r.status_code != 200:
                return []
            new_links = re.findall(r'href=[\'"]?([^\'" >]+)', r.text)
            for link in new_links:
                full = urljoin(url, link)
                try:
                    parsed = urlparse(full)
                    if self.domain in parsed.netloc and parsed.scheme in ("http", "https"):
                        normalized = parsed.scheme + "://" + parsed.netloc + (parsed.path if parsed.path else "/")
                        if normalized not in self.visited and normalized not in found:
                            found.append(normalized)
                            self.links.add(normalized)
                except Exception:
                    pass
        except Exception:
            pass
        return found
