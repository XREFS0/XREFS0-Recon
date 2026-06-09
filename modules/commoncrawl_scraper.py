import requests
from fake_useragent import UserAgent

ua = UserAgent()

class CommonCrawlScraper:
    def __init__(self, domain, timeout=10):
        self.domain = domain
        self.timeout = timeout

    def scrape(self):
        urls = set()
        try:
            r = requests.get(
                "https://index.commoncrawl.org/collinfo.json",
                timeout=self.timeout,
                headers={"User-Agent": ua.random},
            )
            if r.status_code != 200:
                return []
            indexes = r.json()
            if not indexes:
                return []
            latest = indexes[-1]["id"]
            cc_url = f"https://index.commoncrawl.org/CC-MAIN-{latest}-index?url=*.{self.domain}&output=json&limit=1000"
            r2 = requests.get(cc_url, timeout=self.timeout, headers={"User-Agent": ua.random})
            if r2.status_code == 200:
                for line in r2.text.strip().split("\n"):
                    try:
                        import json
                        data = json.loads(line)
                        url = data.get("url", "")
                        if url:
                            urls.add(url)
                    except Exception:
                        continue
        except Exception:
            pass
        return sorted(urls)
