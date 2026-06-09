import requests
import socket
from fake_useragent import UserAgent

ua = UserAgent()

class ASNGeoLookup:
    def __init__(self, timeout=10):
        self.timeout = timeout

    def lookup(self, ip):
        result = {
            "ip": ip,
            "asn": "",
            "asn_org": "",
            "isp": "",
            "country": "",
            "city": "",
            "region": "",
            "latitude": "",
            "longitude": "",
            "organization": "",
        }
        result.update(self._from_ip_api(ip))
        if not result["asn"]:
            result.update(self._from_ipinfo(ip))
        if not result["asn"]:
            result.update(self._from_hackertarget(ip))
        return result

    def _from_ip_api(self, ip):
        res = {}
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=self.timeout, headers={"User-Agent": ua.random})
            if r.status_code == 200:
                data = r.json()
                res["country"] = data.get("country", "")
                res["city"] = data.get("city", "")
                res["region"] = data.get("regionName", "")
                res["latitude"] = str(data.get("lat", ""))
                res["longitude"] = str(data.get("lon", ""))
                res["isp"] = data.get("isp", "")
                res["organization"] = data.get("org", "")
                res["asn"] = data.get("as", "").split(" ")[0] if data.get("as") else ""
                res["asn_org"] = " ".join(data.get("as", "").split(" ")[1:]) if data.get("as") else ""
        except Exception:
            pass
        return res

    def _from_ipinfo(self, ip):
        res = {}
        try:
            r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=self.timeout, headers={"User-Agent": ua.random})
            if r.status_code == 200:
                data = r.json()
                res["country"] = data.get("country", "")
                res["city"] = data.get("city", "")
                res["region"] = data.get("region", "")
                res["latitude"] = data.get("loc", "").split(",")[0] if data.get("loc") else ""
                res["longitude"] = data.get("loc", "").split(",")[1] if data.get("loc") else ""
                res["organization"] = data.get("org", "")
                res["asn"] = data.get("org", "").split(" ")[0] if data.get("org") else ""
        except Exception:
            pass
        return res

    def _from_hackertarget(self, ip):
        res = {}
        try:
            r = requests.get(f"https://api.hackertarget.com/aslookup/?q={ip}", timeout=self.timeout, headers={"User-Agent": ua.random})
            if r.status_code == 200:
                for line in r.text.strip().split("\n"):
                    if "AS" in line:
                        parts = line.split("|")
                        if len(parts) >= 2:
                            res["asn"] = parts[0].strip()
                            res["asn_org"] = parts[1].strip()
        except Exception:
            pass
        return res
