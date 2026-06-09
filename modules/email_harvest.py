import re
import requests
from fake_useragent import UserAgent

ua = UserAgent()

class EmailHarvester:
    def __init__(self, domain, timeout=10):
        self.domain = domain
        self.timeout = timeout

    def harvest(self):
        emails = set()
        emails.update(self._from_webpages())
        emails.update(self._from_whois())
        return sorted(emails)

    def _from_webpages(self):
        emails = set()
        for scheme in ["https", "http"]:
            try:
                url = f"{scheme}://{self.domain}"
                r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random}, verify=False)
                found = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.' + re.escape(self.domain.split(".")[-1]), r.text)
                found += re.findall(r'[a-zA-Z0-9._%+-]+@' + re.escape(self.domain), r.text)
                for e in found:
                    e = e.strip().lower()
                    if self.domain in e:
                        emails.add(e)
                break
            except Exception:
                continue
        return emails

    def _from_whois(self):
        emails = set()
        try:
            import whois
            import sys, io
            old_stderr = sys.stderr
            sys.stderr = io.StringIO()
            w = whois.whois(self.domain)
            sys.stderr = old_stderr
            if w.emails:
                if isinstance(w.emails, list):
                    for e in w.emails:
                        if e and "@" in str(e):
                            emails.add(str(e).strip().lower())
                elif w.emails and "@" in str(w.emails):
                    emails.add(str(w.emails).strip().lower())
        except Exception:
            pass
        return emails
