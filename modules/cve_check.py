import requests
from fake_useragent import UserAgent

ua = UserAgent()

CVE_DATABASE = {
    "WordPress": {
        "versions": {
            "any": ["CVE-2025-*, ongoing WordPress core vulnerabilities"],
            "4.7": ["CVE-2017-1001000", "CVE-2017-1001001"],
            "4.8": ["CVE-2017-17094", "CVE-2017-17095"],
            "4.9": ["CVE-2017-1001002"],
            "5.0": ["CVE-2019-8942", "CVE-2019-8943"],
            "5.1": ["CVE-2019-9787"],
            "5.2": ["CVE-2019-16780"],
            "5.3": ["CVE-2020-11025", "CVE-2020-11026"],
            "5.4": ["CVE-2020-14035"],
            "5.5": ["CVE-2020-28032"],
            "5.6": ["CVE-2021-29447"],
            "5.7": ["CVE-2021-39200"],
            "5.8": ["CVE-2021-39201"],
            "6.0": ["CVE-2022-35915", "CVE-2022-21661"],
            "6.1": ["CVE-2023-2867"],
            "6.2": ["CVE-2023-2868"],
        }
    },
    "Drupal": {
        "versions": {
            "7.0": ["CVE-2018-7600 (Drupalgeddon2)", "CVE-2018-7602"],
            "8.0": ["CVE-2018-7600 (Drupalgeddon2)", "CVE-2018-7602"],
            "9.0": ["CVE-2020-13671"],
        }
    },
    "Joomla": {
        "versions": {
            "3.0": ["CVE-2019-11831", "CVE-2019-11832"],
            "4.0": ["CVE-2023-23752"],
            "4.2": ["CVE-2023-23753"],
        }
    },
    "Apache HTTPD": {
        "versions": {
            "2.4.49": ["CVE-2021-41773 (Path Traversal)"],
            "2.4.50": ["CVE-2021-42013 (RCE)"],
            "2.4.17": ["CVE-2015-3183"],
            "2.4.6": ["CVE-2021-44790"],
            "2.4.0": ["CVE-2006-3747"],
        }
    },
    "Nginx": {
        "versions": {
            "1.20.0": ["CVE-2021-23017"],
            "1.21.0": ["CVE-2022-22774"],
            "1.22.0": ["CVE-2023-44487"],
            "0.8.0": ["CVE-2009-3898"],
        }
    },
    "PHP": {
        "versions": {
            "5.6": ["CVE-2018-5711"],
            "7.0": ["CVE-2019-11043"],
            "7.3": ["CVE-2019-11043"],
            "8.1": ["CVE-2022-31625"],
            "8.2": ["CVE-2024-*"],
        }
    },
    "OpenSSL": {
        "versions": {
            "1.0.1": ["CVE-2014-0160 (Heartbleed)"],
            "1.0.2": ["CVE-2016-0800 (DROWN)"],
            "3.0.0": ["CVE-2022-3786", "CVE-2022-3602"],
            "1.1.1": ["CVE-2023-0464"],
        }
    },
    "IIS": {
        "versions": {
            "6.0": ["CVE-2017-7269 (WebDAV RCE)"],
            "7.5": ["CVE-2010-3972"],
            "8.5": ["CVE-2015-1635 (HTTP.sys)"],
            "10.0": ["CVE-2021-31166"],
        }
    },
    "Tomcat": {
        "versions": {
            "7.0": ["CVE-2017-12615", "CVE-2017-12617"],
            "8.0": ["CVE-2018-11784"],
            "9.0": ["CVE-2024-*"],
        }
    },
    "Jenkins": {
        "versions": {
            "2.0": ["CVE-2024-23897"],
            "2.440": ["CVE-2024-23897"],
        }
    },
    "GitLab": {
        "versions": {
            "13.0": ["CVE-2021-22205"],
            "15.0": ["CVE-2023-5009"],
            "16.0": ["CVE-2023-3932"],
        }
    },
    "Moodle": {
        "versions": {
            "3.0": ["CVE-2024-*"],
            "4.0": ["CVE-2023-4821"],
        }
    },
    "Laravel": {
        "versions": {
            "5.0": ["CVE-2021-3129"],
            "6.0": ["CVE-2021-21263"],
            "8.0": ["CVE-2021-3129"],
        }
    },
    "Django": {
        "versions": {
            "2.2": ["CVE-2024-*"],
            "3.2": ["CVE-2023-31047"],
            "4.0": ["CVE-2023-31047"],
        }
    },
    "Ruby on Rails": {
        "versions": {
            "5.0": ["CVE-2023-22792"],
            "6.0": ["CVE-2023-22795"],
            "7.0": ["CVE-2023-22796"],
        }
    },
    "Plesk": {
        "versions": {
            "18.0": ["CVE-2021-29447"],
        }
    },
    "CPanel": {
        "versions": {
            "100.0": ["CVE-2023-29489"],
        }
    },
    "phpMyAdmin": {
        "versions": {
            "4.0": ["CVE-2018-12613"],
            "5.0": ["CVE-2020-26935"],
        }
    },
    "Elasticsearch": {
        "versions": {
            "7.0": ["CVE-2023-31418"],
            "8.0": ["CVE-2024-*"],
        }
    },
    "Kibana": {
        "versions": {
            "7.0": ["CVE-2024-*"],
            "8.0": ["CVE-2023-31415"],
        }
    },
    "Grafana": {
        "versions": {
            "8.0": ["CVE-2021-43798"],
            "9.0": ["CVE-2023-3128"],
        }
    },
    "Jupyter": {
        "versions": {
            "4.0": ["CVE-2024-*"],
        }
    },
    "Prometheus": {
        "versions": {
            "2.0": ["CVE-2023-40578"],
        }
    },
}

class CVEChecker:
    def __init__(self):
        self._nvd_cache = {}

    def check(self, tech_fingerprints):
        findings = []
        for tech, patterns in tech_fingerprints.items():
            if tech in CVE_DATABASE:
                for version, cves in CVE_DATABASE[tech]["versions"].items():
                    findings.append({
                        "technology": tech,
                        "version": version,
                        "cves": cves,
                        "description": f"Potential CVEs for {tech} {version}: {', '.join(cves)}",
                    })
            live = self.search_nvd(tech)
            if live:
                for cve in live[:3]:
                    findings.append({
                        "technology": tech,
                        "version": "unknown",
                        "cves": [cve["id"]],
                        "description": f"NVD: {cve['description'][:120]}",
                    })
        return findings

    def search_nvd(self, query):
        if query in self._nvd_cache:
            return self._nvd_cache[query]
        results = []
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=5"
            r = requests.get(url, timeout=10, headers={"User-Agent": ua.random})
            if r.status_code == 200:
                data = r.json()
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    results.append({
                        "id": cve.get("id", ""),
                        "description": cve.get("descriptions", [{}])[0].get("value", "") if cve.get("descriptions") else "",
                        "severity": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", ""),
                        "score": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", ""),
                    })
        except Exception:
            pass
        self._nvd_cache[query] = results
        return results
