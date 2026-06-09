import whois
import sys
import io
from datetime import datetime, timezone

class WHOISChecker:
    def __init__(self, domain, timeout=10):
        self.domain = domain
        self.timeout = timeout

    def lookup(self):
        result = {
            "registrar": "",
            "created": "",
            "expires": "",
            "updated": "",
            "status": "",
            "name_servers": [],
            "emails": [],
            "org": "",
            "country": "",
            "is_registered": False,
            "is_expired": False,
            "days_until_expiry": None,
        }
        try:
            old_stderr = sys.stderr
            sys.stderr = io.StringIO()
            w = whois.whois(self.domain)
            sys.stderr = old_stderr
            result["registrar"] = str(w.registrar or "")
            result["created"] = str(w.creation_date or "")
            result["expires"] = str(w.expiration_date or "")
            result["updated"] = str(w.updated_date or "")
            result["name_servers"] = [str(ns) for ns in (w.name_servers or [])]
            result["emails"] = [str(e) for e in (w.emails or [])]
            result["org"] = str(w.org or "")
            result["country"] = str(w.country or "")
            if w.creation_date:
                result["is_registered"] = True
            if w.expiration_date:
                exp = w.expiration_date
                if isinstance(exp, list):
                    exp = exp[0] if exp else None
                if isinstance(exp, datetime):
                    now = datetime.now(timezone.utc)
                    if exp.tzinfo is None:
                        exp = exp.replace(tzinfo=timezone.utc)
                    if now.tzinfo is None:
                        now = now.replace(tzinfo=timezone.utc)
                    result["is_expired"] = exp < now
                    delta = exp - now
                    result["days_until_expiry"] = delta.days
            status_list = w.status or []
            if isinstance(status_list, str):
                status_list = [status_list]
            result["status"] = ", ".join(str(s) for s in status_list)
        except Exception as e:
            sys.stderr = old_stderr
            if "No match for" in str(e) or "NOT FOUND" in str(e) or "No entries found" in str(e):
                result["is_registered"] = False
                result["status"] = "Domain is available (not registered)"
            else:
                result["status"] = f"WHOIS: {str(e)[:80]}"
        return result
