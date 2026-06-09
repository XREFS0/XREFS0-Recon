import requests
from fake_useragent import UserAgent

ua = UserAgent()

class DockerRegistryScanner:
    def __init__(self, domain, timeout=10):
        self.domain = domain
        self.timeout = timeout

    def scan(self):
        results = {"registries": [], "exposed": False}
        targets = [
            f"https://{self.domain}/v2/",
            f"https://{self.domain}/v2/_catalog",
            f"http://{self.domain}:5000/v2/",
            f"http://{self.domain}:5000/v2/_catalog",
            f"https://registry.{self.domain}/v2/",
            f"https://registry.{self.domain}/v2/_catalog",
            f"https://docker.{self.domain}/v2/",
            f"https://docker.{self.domain}/v2/_catalog",
            f"https://docker-registry.{self.domain}/v2/",
            f"https://docker-registry.{self.domain}/v2/_catalog",
        ]
        for url in targets:
            try:
                r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random}, verify=False)
                if r.status_code == 200:
                    data = {}
                    try:
                        data = r.json()
                    except Exception:
                        pass
                    results["registries"].append({
                        "url": url,
                        "accessible": True,
                        "repositories": data.get("repositories", []) if "repositories" in data else [],
                        "api_version": r.headers.get("Docker-Distribution-Api-Version", ""),
                    })
                    results["exposed"] = True
                elif r.status_code == 401:
                    results["registries"].append({
                        "url": url,
                        "accessible": False,
                        "auth_required": True,
                        "api_version": r.headers.get("Docker-Distribution-Api-Version", ""),
                    })
            except Exception:
                continue
        return results
