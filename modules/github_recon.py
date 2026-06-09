import requests
from fake_useragent import UserAgent

ua = UserAgent()

class GitHubRecon:
    def __init__(self, token="", timeout=10):
        self.token = token
        self.timeout = timeout

    def search(self, domain):
        results = {"repositories": [], "code_snippets": [], "issues": [], "users": []}
        if not self.token:
            return results
        headers = {
            "Authorization": f"token {self.token}",
            "User-Agent": ua.random,
            "Accept": "application/vnd.github.v3+json",
        }
        queries = [
            f'"{domain}"',
            f'"{domain}" filename:config',
            f'"{domain}" filename:.env',
            f'"{domain}" filename:.gitignore',
            f'"{domain}" filename:credentials',
            f'"{domain}" language:python',
            f'"{domain}" language:javascript',
            f'"{domain}" language:php',
            f'"{domain}" language:java',
            f'"{domain}" language:ruby',
            f'"{domain}" language:go',
            f'"{domain}" password',
            f'"{domain}" secret',
            f'"{domain}" api.key',
            f'"{domain}" aws.key',
        ]
        for query in queries[:5]:
            try:
                r = requests.get(
                    "https://api.github.com/search/code",
                    params={"q": query, "per_page": 5},
                    headers=headers,
                    timeout=self.timeout,
                )
                if r.status_code == 200:
                    data = r.json()
                    for item in data.get("items", []):
                        results["code_snippets"].append({
                            "repository": item.get("repository", {}).get("full_name", ""),
                            "path": item.get("path", ""),
                            "url": item.get("html_url", ""),
                        })
            except Exception:
                continue
        try:
            r = requests.get(
                "https://api.github.com/search/repositories",
                params={"q": domain, "per_page": 10, "sort": "updated"},
                headers=headers,
                timeout=self.timeout,
            )
            if r.status_code == 200:
                data = r.json()
                for item in data.get("items", []):
                    results["repositories"].append({
                        "name": item.get("full_name", ""),
                        "url": item.get("html_url", ""),
                        "description": item.get("description", ""),
                        "stars": item.get("stargazers_count", 0),
                        "forks": item.get("forks_count", 0),
                    })
        except Exception:
            pass
        return results
