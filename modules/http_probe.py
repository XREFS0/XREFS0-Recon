import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from fake_useragent import UserAgent
import re

ua = UserAgent()

HTTP_PORTS = [80, 443, 8080, 8443, 2082, 2083, 2095, 2096]

class HTTPProber:
    def __init__(self, timeout=10):
        self.timeout = timeout

    def probe(self, hostname, ports=None):
        if ports is None:
            ports = HTTP_PORTS
        result = {
            "hostname": hostname,
            "url": "",
            "status_code": 0,
            "title": "",
            "server": "",
            "content_type": "",
            "content_length": 0,
            "redirect_url": "",
            "tech_stack": [],
            "alive": False,
            "ports_alive": [],
        }
        for port in ports:
            for scheme in ["https", "http"]:
                if (scheme == "https" and port == 80) or (scheme == "http" and port == 443):
                    continue
                try:
                    url = f"{scheme}://{hostname}:{port}" if port not in [80, 443] else f"{scheme}://{hostname}"
                    r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random}, verify=False, allow_redirects=True)
                    result["url"] = r.url
                    result["status_code"] = r.status_code
                    result["server"] = r.headers.get("Server", "")
                    result["content_type"] = r.headers.get("Content-Type", "")
                    result["content_length"] = len(r.content)
                    result["alive"] = True
                    result["ports_alive"].append(port)
                    if r.history:
                        result["redirect_url"] = r.url
                    title_match = re.search(r'<title[^>]*>([^<]+)</title>', r.text, re.IGNORECASE)
                    if title_match:
                        result["title"] = title_match.group(1).strip()
                    break
                except requests.exceptions.SSLError:
                    continue
                except Exception:
                    continue
            if result["alive"]:
                break
        return result

    def probe_many(self, hostnames, max_workers=30, ports=None):
        results = {}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.probe, h, ports): h for h in hostnames}
            for f in as_completed(futures):
                res = f.result()
                results[res["hostname"]] = res
        return results
