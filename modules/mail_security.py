import dns.resolver
from fake_useragent import UserAgent

ua = UserAgent()

class MailSecurityChecker:
    def __init__(self, domain, timeout=10):
        self.domain = domain
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def check_all(self):
        return {
            "spf": self._check_spf(),
            "dkim": self._check_dkim(),
            "dmarc": self._check_dmarc(),
            "mx": self._check_mx(),
        }

    def _check_spf(self):
        result = {"present": False, "records": [], "issues": []}
        try:
            answers = self.resolver.resolve(self.domain, "TXT", lifetime=self.timeout)
            for r in answers:
                txt = str(r)
                if txt.startswith("v=spf1"):
                    result["present"] = True
                    result["records"].append(txt)
                    if "+all" in txt or "?all" in txt:
                        result["issues"].append("Weak SPF policy: +all or ?all allows any sender")
                    if "-all" not in txt:
                        result["issues"].append("SPF should end with -all (hard fail) for strict security")
                    if "~all" in txt:
                        result["issues"].append("SPF uses ~all (soft fail) - consider -all for strict security")
        except Exception:
            result["issues"].append("No SPF record found")
        return result

    def _check_dkim(self):
        result = {"present": False, "selectors": [], "issues": []}
        common_selectors = ["default", "google", "selector1", "selector2", "dkim", "mail", "zoho", "mandrill", "sparkpost", "sendgrid", "mailgun"]
        for sel in common_selectors:
            try:
                dkim_domain = f"{sel}._domainkey.{self.domain}"
                self.resolver.resolve(dkim_domain, "TXT", lifetime=self.timeout)
                result["present"] = True
                result["selectors"].append(sel)
            except Exception:
                continue
        return result

    def _check_dmarc(self):
        result = {"present": False, "records": [], "issues": [], "policy": ""}
        try:
            answers = self.resolver.resolve(f"_dmarc.{self.domain}", "TXT", lifetime=self.timeout)
            for r in answers:
                txt = str(r)
                if txt.startswith("v=DMARC1"):
                    result["present"] = True
                    result["records"].append(txt)
                    if "p=reject" in txt:
                        result["policy"] = "reject"
                    elif "p=quarantine" in txt:
                        result["policy"] = "quarantine"
                        result["issues"].append("DMARC policy is quarantine, consider reject for best protection")
                    elif "p=none" in txt:
                        result["policy"] = "none"
                        result["issues"].append("DMARC policy is none - no enforcement")
                    if "rua=" in txt:
                        import re
                        report_emails = re.findall(r'mailto:([^\]]+)', txt)
                        result["report_emails"] = report_emails
        except Exception:
            result["issues"].append("No DMARC record found")
        return result

    def _check_mx(self):
        result = {"present": False, "records": [], "providers": []}
        try:
            answers = self.resolver.resolve(self.domain, "MX", lifetime=self.timeout)
            result["present"] = True
            for r in answers:
                mx_str = str(r.exchange).rstrip(".")
                result["records"].append({"priority": r.preference, "host": mx_str})
                mx_lower = mx_str.lower()
                if "google" in mx_lower or "googlemail" in mx_lower:
                    result["providers"].append("Google Workspace")
                elif "outlook" in mx_lower or "microsoft" in mx_lower or "protection.outlook" in mx_lower:
                    result["providers"].append("Microsoft 365")
                elif "zoho" in mx_lower:
                    result["providers"].append("Zoho")
                elif "protonmail" in mx_lower or "proton" in mx_lower:
                    result["providers"].append("ProtonMail")
                elif "yandex" in mx_lower:
                    result["providers"].append("Yandex")
                elif "mailgun" in mx_lower:
                    result["providers"].append("Mailgun")
                elif "sendgrid" in mx_lower:
                    result["providers"].append("SendGrid")
        except Exception:
            pass
        return result
