import requests
from fake_useragent import UserAgent
import re

ua = UserAgent()

S3_BUCKET_PATTERNS = [
    "{domain}",
    "{domain}-backup",
    "{domain}-backups",
    "{domain}-data",
    "{domain}-assets",
    "{domain}-static",
    "{domain}-media",
    "{domain}-uploads",
    "{domain}-files",
    "{domain}-logs",
    "{domain}-config",
    "{domain}-dev",
    "{domain}-staging",
    "{domain}-prod",
    "{domain}-test",
    "{domain}-archive",
    "{domain}-storage",
    "{domain}-cdn",
    "{domain}-bucket",
    "{domain}-s3",
    "aws-{domain}",
]

class S3Scanner:
    def __init__(self, timeout=10):
        self.timeout = timeout

    def scan(self, domain):
        results = []
        from concurrent.futures import ThreadPoolExecutor, as_completed
        domain_parts = domain.split(".")
        tld = domain_parts[-1] if len(domain_parts) > 1 else ""
        base = domain_parts[0] if len(domain_parts) > 0 else domain
        bucket_names = [pattern.format(domain=base, tld=tld, full=domain) for pattern in S3_BUCKET_PATTERNS]
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self._check_bucket, bn): bn for bn in bucket_names}
            for f in as_completed(futures):
                try:
                    result = f.result()
                    if result:
                        results.append(result)
                except Exception:
                    continue
        return results

    def _check_bucket(self, bucket_name):
        result = {"bucket": bucket_name, "exists": False, "public": False, "files": [], "urls": []}
        endpoints = [
            f"https://{bucket_name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket_name}",
        ]
        for url in endpoints:
            try:
                r = requests.get(url, timeout=min(self.timeout, 3), headers={"User-Agent": ua.random})
                if r.status_code == 200:
                    result["exists"] = True
                    result["public"] = True
                    result["urls"].append(url)
                    if "Contents" in r.text or "Key" in r.text:
                        import xml.etree.ElementTree as ET
                        try:
                            root = ET.fromstring(r.content)
                            ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
                            for content in root.findall(".//s3:Contents/s3:Key", ns):
                                result["files"].append(content.text)
                        except Exception:
                            pass
                    break
                elif r.status_code == 403:
                    result["urls"].append(url)
                    break
            except Exception:
                continue
        return result if result["exists"] else None
