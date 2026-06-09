import dns.resolver
import dns.reversename
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket

class ReverseDNS:
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def lookup(self, ips):
        results = {}
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(self._ptr_lookup, ip): ip for ip in ips}
            for f in as_completed(futures):
                ip = futures[f]
                try:
                    ptr = f.result()
                    if ptr:
                        results[ip] = ptr
                except Exception:
                    pass
        return results

    def _ptr_lookup(self, ip):
        try:
            addr = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(addr, "PTR", lifetime=self.timeout)
            return [str(a).rstrip(".") for a in answers]
        except Exception:
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                return [hostname]
            except Exception:
                return None

    def enumerate_network(self, cidr, limit=256):
        results = {}
        import ipaddress
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            hosts = list(network.hosts())[:limit]
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(self._ptr_lookup, str(ip)): str(ip) for ip in hosts}
                for f in as_completed(futures):
                    ip = futures[f]
                    try:
                        ptr = f.result()
                        if ptr:
                            results[ip] = ptr
                    except Exception:
                        pass
        except Exception:
            pass
        return results
