import requests
from fake_useragent import UserAgent

ua = UserAgent()

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HTTP Strict Transport Security (HSTS) - enforces HTTPS",
        "rating": "critical",
        "expected": "max-age=31536000"
    },
    "Content-Security-Policy": {
        "description": "Content Security Policy - prevents XSS attacks",
        "rating": "critical",
        "expected": "present"
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking by controlling iframe embedding",
        "rating": "high",
        "expected": "DENY|SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing",
        "rating": "high",
        "expected": "nosniff"
    },
    "X-XSS-Protection": {
        "description": "Cross-site scripting filter",
        "rating": "medium",
        "expected": "1; mode=block"
    },
    "Referrer-Policy": {
        "description": "Controls referrer information sent with requests",
        "rating": "medium",
        "expected": "strict-origin-when-cross-origin|no-referrer"
    },
    "Permissions-Policy": {
        "description": "Controls browser features and APIs",
        "rating": "medium",
        "expected": "present"
    },
    "Access-Control-Allow-Origin": {
        "description": "CORS header - should be carefully configured",
        "rating": "medium",
        "expected": "not '*'"
    },
    "Set-Cookie": {
        "description": "Cookies should have Secure, HttpOnly, SameSite flags",
        "rating": "high",
        "expected": "secure|httponly|samesite"
    },
    "Cache-Control": {
        "description": "Controls caching behavior",
        "rating": "low",
        "expected": "no-store|private"
    },
    "Pragma": {
        "description": "Backwards compatibility for cache control",
        "rating": "low",
        "expected": "no-cache"
    },
}

class SecurityHeadersChecker:
    def __init__(self, timeout=10):
        self.timeout = timeout

    def check(self, url):
        result = {"url": url, "headers": {}, "findings": []}
        try:
            r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random}, verify=False, allow_redirects=True)
            result["status_code"] = r.status_code
            result["final_url"] = r.url
            for hdr, info in SECURITY_HEADERS.items():
                value = r.headers.get(hdr, "")
                finding = {
                    "header": hdr,
                    "present": bool(value),
                    "value": value,
                    "description": info["description"],
                    "rating": info["rating"],
                }
                if value:
                    result["headers"][hdr] = value
                result["findings"].append(finding)
        except Exception as e:
            result["error"] = str(e)
        return result
