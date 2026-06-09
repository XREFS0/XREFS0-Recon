import os
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from fake_useragent import UserAgent

ua = UserAgent()

WORDLIST_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists", "dirs.txt")

class DirEnumerator:
    def __init__(self, base_url, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def enumerate(self, paths=None, max_workers=30):
        if paths is None:
            paths = self._load_wordlist()
        results = []
        def check_path(path):
            url = f"{self.base_url}{path}"
            try:
                r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random}, verify=False, allow_redirects=False)
                if r.status_code not in [404, 410]:
                    return {
                        "url": url,
                        "status": r.status_code,
                        "size": len(r.content),
                        "redirect": r.headers.get("Location", ""),
                    }
            except Exception:
                pass
            return None
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(check_path, p) for p in paths]
            for f in as_completed(futures):
                res = f.result()
                if res:
                    results.append(res)
        results.sort(key=lambda x: x["url"])
        return results

    def _load_wordlist(self):
        if os.path.exists(WORDLIST_PATH):
            with open(WORDLIST_PATH, "r", encoding="utf-8") as f:
                paths = [line.strip() for line in f if line.strip()]
                if paths:
                    return paths
        return ["/", "/admin", "/login", "/wp-admin", "/robots.txt", "/sitemap.xml", "/.env", "/.git/config"]
