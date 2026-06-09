import dns.resolver
import dns.name
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

WORDLIST_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists", "subdomains.txt")

class DNSBruteforcer:
    def __init__(self, domain, wordlist=WORDLIST_PATH, resolvers=None, timeout=5):
        self.domain = domain
        self.wordlist = wordlist
        self.timeout = timeout
        self._resolvers = resolvers or ["1.1.1.1", "8.8.8.8", "1.0.0.1"]

    def brute(self, max_workers=50):
        found = []
        subs = self._load_wordlist()
        if not subs:
            return found
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self._check, sub): sub for sub in subs}
            for f in as_completed(futures):
                try:
                    result = f.result()
                    if result:
                        found.append(result)
                except Exception:
                    pass
        return sorted(found)

    def _load_wordlist(self):
        if not os.path.exists(self.wordlist):
            return []
        with open(self.wordlist, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]

    def _check(self, sub):
        hostname = f"{sub}.{self.domain}"
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = min(4, self.timeout)
            system_ns = list(resolver.nameservers)
            resolver.nameservers = system_ns + self._resolvers
            answers = resolver.resolve(hostname, "A", lifetime=min(4, self.timeout))
            ips = [str(r) for r in answers]
            return {"hostname": hostname, "ip": ips[0] if ips else ""}
        except Exception:
            return None
