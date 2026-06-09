import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from fake_useragent import UserAgent

ua = UserAgent()

GCP_BUCKET_PATTERNS = [
    "{domain}",
    "{domain}-backup",
    "{domain}-backups",
    "{domain}-data",
    "{domain}-storage",
    "{domain}-assets",
    "{domain}-files",
    "{domain}-media",
    "{domain}-public",
    "{domain}-static",
    "{domain}-uploads",
    "{domain}-logs",
    "{domain}-backup-01",
    "{domain}-backup-02",
    "{domain}-dev",
    "{domain}-prod",
    "{domain}-staging",
    "{domain}-test",
    "{domain}-config",
    "{domain}-db",
    "{domain}-database",
    "{domain}-archive",
    "backup-{domain}",
    "data-{domain}",
    "storage-{domain}",
    "assets-{domain}",
    "uploads-{domain}",
    "media-{domain}",
    "static-{domain}",
    "public-{domain}",
    "{domain}-01",
    "{domain}-02",
    "{domain}-primary",
    "{domain}-secondary",
    "{domain}-main",
    "prod-{domain}",
    "dev-{domain}",
    "staging-{domain}",
    "test-{domain}",
    "backups-{domain}",
    "logs-{domain}",
]

AZURE_BLOB_PATTERNS = [
    "{domain}",
    "{domain}backup",
    "{domain}data",
    "{domain}storage",
    "{domain}assets",
    "{domain}files",
    "{domain}media",
    "{domain}public",
    "{domain}static",
    "{domain}uploads",
    "{domain}logs",
    "{domain}dev",
    "{domain}prod",
    "{domain}staging",
    "{domain}test",
    "{domain}config",
    "{domain}archive",
    "backup{domain}",
    "data{domain}",
    "storage{domain}",
    "assets{domain}",
    "uploads{domain}",
    "media{domain}",
    "static{domain}",
    "public{domain}",
    "prod{domain}",
    "dev{domain}",
    "staging{domain}",
    "test{domain}",
]

class CloudScanner:
    def __init__(self, domain, timeout=5):
        self.domain = domain.replace(".", "-").replace("_", "-").lower()
        self.orig_domain = domain
        self.timeout = timeout

    def scan_all(self):
        results = {"gcp": [], "azure": []}
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {}
            for name in GCP_BUCKET_PATTERNS:
                bucket = name.format(domain=self.domain)
                url = f"https://storage.googleapis.com/{bucket}"
                futures[executor.submit(self._check_gcp, url, bucket)] = "gcp"
                url2 = f"https://www.googleapis.com/storage/v1/b/{bucket}"
                futures[executor.submit(self._check_gcp_api, url2, bucket)] = "gcp"
            for name in AZURE_BLOB_PATTERNS:
                container = name.format(domain=self.domain)
                url = f"https://{container}.blob.core.windows.net"
                futures[executor.submit(self._check_azure, url, container)] = "azure"
            for f in as_completed(futures):
                try:
                    result = f.result()
                    if result:
                        results[futures[f]].append(result)
                except Exception:
                    pass
        return results

    def _check_gcp(self, url, bucket):
        try:
            r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random})
            if r.status_code == 200:
                return {"provider": "GCP", "type": "public_bucket", "url": url, "bucket": bucket, "accessible": True}
            if r.status_code == 403:
                return {"provider": "GCP", "type": "restricted_bucket", "url": url, "bucket": bucket, "accessible": False}
        except Exception:
            pass
        return None

    def _check_gcp_api(self, url, bucket):
        try:
            r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random})
            if r.status_code == 200:
                return {"provider": "GCP", "type": "public_bucket_api", "url": url, "bucket": bucket, "accessible": True}
        except Exception:
            pass
        return None

    def _check_azure(self, url, container):
        try:
            r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random})
            if r.status_code in [200, 403]:
                if "PublicAccess" in r.text or "Container" in r.text or r.status_code == 200:
                    return {"provider": "Azure", "type": "blob_container", "url": url, "container": container, "accessible": r.status_code == 200}
        except Exception:
            pass
        return None
