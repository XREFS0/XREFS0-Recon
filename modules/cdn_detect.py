import requests
from fake_useragent import UserAgent

ua = UserAgent()

CDN_SIGNATURES = {
    "Cloudflare": ["cloudflare", "__cfduid", "cf-ray", "cf-request-id"],
    "Akamai": ["akamai", "akamaized", "akamaihd", "X-Akamai-"],
    "Amazon CloudFront": ["cloudfront", "x-amz-cf-id", "x-amz-cf-pop"],
    "Incapsula": ["incapsula", "X-Iinfo"],
    "Sucuri": ["sucuri", "X-Sucuri-ID"],
    "Fastly": ["fastly", "X-Served-By", "X-Cache-Hits"],
    "KeyCDN": ["keycdn", "X-Edge-Location"],
    "StackPath": ["stackpath", "stackpathdns"],
    "CDN77": ["cdn77", "xcdn77-"],
    "Azure CDN": ["azureedge", "x-azure-ref"],
    "Google Cloud CDN": ["gcpcdn", "x-goog-"],
    "Imperva": ["imperva", "incapsula"],
}

class CDNDetector:
    def __init__(self, timeout=10):
        self.timeout = timeout

    def detect(self, hostname):
        result = {"cdns": [], "headers": {}}
        try:
            url = f"https://{hostname}" if not hostname.startswith("http") else hostname
            r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random}, verify=False, allow_redirects=True)
            result["headers"] = dict(r.headers)
            combined = str(r.headers).lower()
            for cdn_name, signatures in CDN_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in combined:
                        result["cdns"].append({"name": cdn_name, "matched": sig})
                        break
            result["status_code"] = r.status_code
            result["server"] = r.headers.get("Server", "")
        except requests.exceptions.SSLError:
            try:
                url = f"http://{hostname}" if not hostname.startswith("http") else hostname.replace("https://", "http://")
                r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random}, allow_redirects=True)
                result["headers"] = dict(r.headers)
                combined = str(r.headers).lower()
                for cdn_name, signatures in CDN_SIGNATURES.items():
                    for sig in signatures:
                        if sig.lower() in combined:
                            result["cdns"].append({"name": cdn_name, "matched": sig})
                            break
                result["status_code"] = r.status_code
                result["server"] = r.headers.get("Server", "")
            except Exception:
                pass
        except Exception:
            pass
        return result

    def is_cloudflare(self, hostname):
        result = self.detect(hostname)
        for cdn in result.get("cdns", []):
            if "cloudflare" in cdn["name"].lower():
                return True
        return False
