import requests
from fake_useragent import UserAgent
import http.cookiejar

ua = UserAgent()

class CookieChecker:
    def __init__(self, timeout=10):
        self.timeout = timeout

    def check(self, url):
        result = {"url": url, "cookies": [], "findings": []}
        try:
            r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random}, verify=False, allow_redirects=True)
            for cookie in r.cookies:
                c = {
                    "name": cookie.name,
                    "value": cookie.value[:20] + "..." if len(cookie.value) > 20 else cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": cookie.secure,
                    "httponly": cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly"),
                    "samesite": cookie.get_nonstandard_attr("SameSite", "not set"),
                    "expires": cookie.expires,
                }
                issues = []
                if not cookie.secure:
                    issues.append("Missing Secure flag - cookie sent over HTTP")
                if not (cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly")):
                    issues.append("Missing HttpOnly flag - accessible via JavaScript")
                same_site = cookie.get_nonstandard_attr("SameSite", "").lower()
                if not same_site or same_site == "none":
                    issues.append("SameSite not set to Lax/Strict - vulnerable to CSRF")
                if issues:
                    c["issues"] = issues
                    result["findings"].append({"cookie": cookie.name, "issues": issues})
                result["cookies"].append(c)
        except Exception as e:
            result["error"] = str(e)
        return result
