import requests
from fake_useragent import UserAgent

ua = UserAgent()

class CORSChecker:
    def __init__(self, timeout=10):
        self.timeout = timeout

    def check(self, url):
        result = {"url": url, "vulnerable": False, "details": {}}
        test_origins = [
            "https://evil.com",
            "null",
            "https://attacker.evil.com",
        ]
        findings = []
        for origin in test_origins:
            try:
                r = requests.get(
                    url,
                    timeout=self.timeout,
                    headers={
                        "User-Agent": ua.random,
                        "Origin": origin,
                    },
                    verify=False,
                    allow_redirects=False,
                )
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")
                if acao == origin or acao == "*":
                    vuln = {
                        "origin": origin,
                        "acao": acao,
                        "acac": acac == "true",
                        "credentialed": acac == "true",
                    }
                    findings.append(vuln)
                    if acao == origin or (acao == "*" and acac == "true"):
                        result["vulnerable"] = True
            except Exception:
                continue
        result["findings"] = findings
        return result
