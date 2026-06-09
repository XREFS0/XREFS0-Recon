import dns.resolver
import dns.query
import dns.zone
import dns.name
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket

class DNSLookup:
    def __init__(self, domain, timeout=10, resolvers=None):
        self.domain = domain
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        if resolvers:
            system_ns = list(self.resolver.nameservers)
            self.resolver.nameservers = system_ns + resolvers

    def lookup_all(self, subdomains=None):
        targets = [self.domain]
        if subdomains:
            targets = list(set([self.domain] + list(subdomains)))
        results = {}
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self._resolve_all_records, t): t for t in targets}
            for f in as_completed(futures):
                target = futures[f]
                try:
                    records = f.result()
                    if records:
                        results[target] = records
                except Exception:
                    pass
        return results

    def _resolve_all_records(self, hostname):
        records = {}
        per_type_timeout = min(4, self.timeout)
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
        is_subdomain = hostname != self.domain
        if is_subdomain:
            record_types = ["A", "AAAA", "CNAME", "TXT"]
        for rtype in record_types:
            try:
                answers = self.resolver.resolve(hostname, rtype, lifetime=per_type_timeout)
                if rtype in ["MX"]:
                    records[rtype] = [str(r.exchange).rstrip(".") for r in answers]
                elif rtype in ["SOA"]:
                    soa = answers[0]
                    records[rtype] = {
                        "mname": str(soa.mname),
                        "rname": str(soa.rname),
                        "serial": soa.serial,
                        "refresh": soa.refresh,
                        "retry": soa.retry,
                        "expire": soa.expire,
                        "minimum": soa.minimum,
                    }
                elif rtype in ["NS"]:
                    records[rtype] = [str(r).rstrip(".") for r in answers]
                else:
                    records[rtype] = [str(r) for r in answers]
            except Exception:
                continue
        return records

    def check_axfr(self, nameservers=None):
        if not nameservers:
            try:
                answers = self.resolver.resolve(self.domain, "NS", lifetime=min(4, self.timeout))
                nameservers = [str(ns).rstrip(".") for ns in answers]
            except Exception:
                return []
        vulnerable = []
        for ns in nameservers:
            try:
                ns_ip = socket.gethostbyname(ns)
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, lifetime=self.timeout))
                if zone:
                    records = []
                    for name, node in zone.nodes.items():
                        rrsets = node.rdatasets
                        for rdataset in rrsets:
                            for rdata in rdataset:
                                records.append(f"{str(name)}.{self.domain} {rdataset.rdtype} {rdata}")
                    vulnerable.append({"nameserver": ns, "records": records})
            except Exception:
                continue
        return vulnerable
