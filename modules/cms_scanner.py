import requests
import re
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from fake_useragent import UserAgent

ua = UserAgent()

CMS_FINGERPRINTS = {
    "WordPress": {
        "paths": ["/wp-admin/", "/wp-login.php", "/wp-content/", "/wp-includes/", "/wp-json/", "/xmlrpc.php"],
        "headers": {},
        "body_patterns": [r'wp-content', r'wp-includes', r'<meta\s+name="generator"\s+content="WordPress'],
        "version_patterns": [(r'<meta name="generator" content="WordPress ([^"]+)"', 1), (r'/wp-json/\?ver=([^"\']+)', 1)],
    },
    "Drupal": {
        "paths": ["/sites/default/", "/core/", "/includes/", "/misc/", "/modules/", "/profiles/", "/themes/", "/node/"],
        "headers": {"x-drupal-cache": "", "x-generator": "Drupal"},
        "body_patterns": [r'Drupal', r'drupal.js', r'Drupal.settings'],
        "version_patterns": [(r'<meta name="Generator" content="Drupal ([^"]+)"', 1)],
    },
    "Joomla": {
        "paths": ["/administrator/", "/components/", "/modules/", "/plugins/", "/templates/", "/language/", "/includes/"],
        "headers": {"x-content-encoded-by": "Joomla"},
        "body_patterns": [r'Joomla', r'com_content', r'com_modules', r'joomla'],
        "version_patterns": [(r'<meta name="generator" content="Joomla!? ([^"]+)"', 1)],
    },
    "Magento": {
        "paths": ["/static/", "/media/", "/pub/", "/setup/", "/admin/", "/magento_version"],
        "headers": {},
        "body_patterns": [r'Magento\s+v', r'Mage\.js'],
        "version_patterns": [(r'Magento[\/\s]+v?(\d+\.\d+)', 1)],
    },
    "Shopify": {
        "paths": [],
        "headers": {"x-shopid": "", "x-shopify-stage": ""},
        "body_patterns": [r'shopify', r'myshopify\.com', r'Shopify\.'],
        "version_patterns": [],
    },
    "PrestaShop": {
        "paths": ["/modules/", "/themes/", "/img/", "/upload/", "/pdf/", "/js/"],
        "headers": {"powered-by": "PrestaShop"},
        "body_patterns": [r'PrestaShop', r'prestashop'],
        "version_patterns": [(r'<meta name="generator" content="PrestaShop ([^"]+)"', 1)],
    },
    "Django CMS": {
        "paths": [],
        "headers": {"x-powered-by": "Django"},
        "body_patterns": [r'django\.cms', r'CMS_TOOLBAR', r'cms-plugin'],
        "version_patterns": [],
    },
    "TYPO3": {
        "paths": ["/typo3/", "/typo3conf/", "/typo3temp/", "/uploads/"],
        "headers": {"x-typo3-": ""},
        "body_patterns": [r'TYPO3', r'typo3', r'Content Management Framework'],
        "version_patterns": [(r'TYPO3[\/\s]+CMS[\/\s]*(\d+\.\d+)', 1)],
    },
    "Concrete5": {
        "paths": ["/concrete/", "/packages/", "/application/"],
        "headers": {},
        "body_patterns": [r'Concrete5', r'concrete5'],
        "version_patterns": [(r'<meta name="generator" content="concrete5[-\s]+([^"]+)"', 1)],
    },
    "Squarespace": {
        "paths": [],
        "headers": {"x-served-by": "Squarespace"},
        "body_patterns": [r'Squarespace', r'squarespace'],
        "version_patterns": [],
    },
    "Wix": {
        "paths": [],
        "headers": {"x-wix-": ""},
        "body_patterns": [r'Wix\.', r'wix.com', r'X-Wix-'],
        "version_patterns": [],
    },
    "Weebly": {
        "paths": [],
        "headers": {},
        "body_patterns": [r'Weebly', r'weebly'],
        "version_patterns": [],
    },
    "Laravel": {
        "paths": [],
        "headers": {"x-powered-by": "Laravel"},
        "body_patterns": [r'Laravel', r'csrf-token" content="', r'livewire'],
        "version_patterns": [],
    },
    "Symfony": {
        "paths": [],
        "headers": {"x-powered-by": "Symfony"},
        "body_patterns": [r'Symfony', r'profiler', r'_sf2_attributes'],
        "version_patterns": [(r'Symfony[\/\s]+(\d+\.\d+)', 1)],
    },
    "Yii": {
        "paths": [],
        "headers": {},
        "body_patterns": [r'yii', r'Yii\.Base', r'csrf-token" content='],
        "version_patterns": [(r'Yii[\/\s]+(\d+\.\d+)', 1)],
    },
    "ASP.NET": {
        "paths": [],
        "headers": {"x-aspnet-version": ""},
        "body_patterns": [r'__VIEWSTATE', r'__EVENTVALIDATION', r'ASP\.NET'],
        "version_patterns": [(r'X-AspNet-Version[:\s]+([^\r\n]+)', 1)],
    },
    "SharePoint": {
        "paths": [],
        "headers": {"x-sharepointhealthscore": "", "microsoftsharepointteamservices": ""},
        "body_patterns": [r'SharePoint', r'_spBodyOnLoad'],
        "version_patterns": [],
    },
    "Ruby on Rails": {
        "paths": [],
        "headers": {"x-powered-by": "Phusion", "x-request-id": ""},
        "body_patterns": [r'rails', r'csrf-param', r'csrf-token'],
        "version_patterns": [(r'Rails[\/\s]+(\d+\.\d+)', 1)],
    },
    "Express": {
        "paths": [],
        "headers": {"x-powered-by": "Express"},
        "body_patterns": [r'express', r'connect\.session'],
        "version_patterns": [],
    },
    "Next.js": {
        "paths": [],
        "headers": {"x-powered-by": "Next.js"},
        "body_patterns": [r'__NEXT_DATA__', r'/_next/static/', r'nextjs'],
        "version_patterns": [],
    },
    "Nuxt.js": {
        "paths": [],
        "headers": {},
        "body_patterns": [r'__NUXT__', r'_nuxt/', r'nuxt'],
        "version_patterns": [],
    },
    "Gatsby": {
        "paths": [],
        "headers": {"x-powered-by": "Gatsby"},
        "body_patterns": [r'gatsby', r'___gatsby'],
        "version_patterns": [],
    },
    "Vue.js": {
        "paths": [],
        "headers": {},
        "body_patterns": [r'vue\.js', r'vue\.min\.js', r'__VUE__', r'data-v-'],
        "version_patterns": [],
    },
    "Angular": {
        "paths": [],
        "headers": {},
        "body_patterns": [r'angular\.js', r'angular\.min\.js', r'ng-app', r'ng-version'],
        "version_patterns": [(r'ng-version="(\d+\.\d+\.\d+)"', 1)],
    },
    "React": {
        "paths": [],
        "headers": {},
        "body_patterns": [r'react\.js', r'react\.min\.js', r'react-dom', r'__REACT_'],
        "version_patterns": [],
    },
    "Ghost": {
        "paths": ["/ghost/", "/ghost/api/"],
        "headers": {"x-powered-by": "Ghost"},
        "body_patterns": [r'Ghost', r'ghost'],
        "version_patterns": [(r'Ghost[\/\s]+(\d+\.\d+)', 1)],
    },
    "Hugo": {
        "paths": [],
        "headers": {},
        "body_patterns": [r'Hugo', r'hugo\.json'],
        "version_patterns": [(r'Hugo[\/\s]+(\d+\.\d+)', 1)],
    },
    "Jekyll": {
        "paths": [],
        "headers": {},
        "body_patterns": [r'Jekyll', r'jekyll'],
        "version_patterns": [(r'Jekyll[\/\s]+(\d+\.\d+)', 1)],
    },
    "DokuWiki": {
        "paths": ["/doku.php", "/lib/", "/conf/"],
        "headers": {},
        "body_patterns": [r'DokuWiki', r'dokuwiki'],
        "version_patterns": [(r'DokuWiki[\/\s]+(\d+[-]\d+[-]\d+)', 1)],
    },
    "MediaWiki": {
        "paths": ["/wiki/", "/w/", "/mw-config/"],
        "headers": {},
        "body_patterns": [r'MediaWiki', r'mw\.js'],
        "version_patterns": [(r'MediaWiki[\/\s]+(\d+\.\d+)', 1)],
    },
    "phpBB": {
        "paths": ["/phpbb/", "/forums/"],
        "headers": {},
        "body_patterns": [r'phpBB', r'phpbb'],
        "version_patterns": [(r'phpBB[\/\s]+(\d+\.\d+)', 1)],
    },
    "vBulletin": {
        "paths": [],
        "headers": {},
        "body_patterns": [r'vBulletin', r'vb\.js', r'vbulletin'],
        "version_patterns": [(r'vBulletin[\/\s]*(\d+\.\d+)', 1)],
    },
    "XenForo": {
        "paths": [],
        "headers": {},
        "body_patterns": [r'XenForo', r'xenforo'],
        "version_patterns": [(r'XenForo[\/\s]+(\d+\.\d+)', 1)],
    },
    "IPBoard": {
        "paths": [],
        "headers": {},
        "body_patterns": [r'IP\.Board', r'ips4', r'ips\.js'],
        "version_patterns": [],
    },
    "OpenCart": {
        "paths": ["/admin/", "/catalog/", "/system/"],
        "headers": {},
        "body_patterns": [r'OpenCart', r'opencart'],
        "version_patterns": [(r'OpenCart[\/\s]+(\d+\.\d+)', 1)],
    },
    "WHMCS": {
        "paths": ["/whmcs/", "/includes/", "/templates/"],
        "headers": {},
        "body_patterns": [r'WHMCS', r'whmcs'],
        "version_patterns": [(r'WHMCS[\/\s]+(\d+\.\d+)', 1)],
    },
    "CPanel": {
        "paths": ["/cpanel/", "/whm/", "/webmail/"],
        "headers": {},
        "body_patterns": [r'cPanel', r'cpanel', r'WHM'],
        "version_patterns": [],
    },
    "Plesk": {
        "paths": [],
        "headers": {"x-powered-by-plesk": ""},
        "body_patterns": [r'Plesk', r'plesk'],
        "version_patterns": [(r'Plesk[\/\s]+(\d+\.\d+)', 1)],
    },
    "Tomcat": {
        "paths": ["/manager/", "/examples/", "/docs/", "/host-manager/"],
        "headers": {"x-powered-by": "Tomcat", "x-powered-by": "Servlet"},
        "body_patterns": [r'Apache Tomcat', r'tomcat'],
        "version_patterns": [(r'Apache Tomcat[\/\s]+(\d+\.\d+)', 1)],
    },
    "Jetty": {
        "paths": [],
        "headers": {"x-powered-by": "Jetty"},
        "body_patterns": [r'Jetty', r'jetty'],
        "version_patterns": [(r'Jetty[\/\s]+(\d+\.\d+)', 1)],
    },
    "IIS": {
        "paths": [],
        "headers": {"microsoft-iis": "", "x-powered-by": "ASP.NET"},
        "body_patterns": [r'IIS', r'iis'],
        "version_patterns": [(r'IIS[\/\s]+(\d+\.\d+)', 1)],
    },
    "Nginx": {
        "paths": [],
        "headers": {"server": "nginx"},
        "body_patterns": [r'nginx'],
        "version_patterns": [(r'nginx[\/\s]+(\d+\.\d+)', 1)],
    },
    "Apache HTTPD": {
        "paths": [],
        "headers": {"server": "Apache"},
        "body_patterns": [r'Apache', r'apache'],
        "version_patterns": [(r'Apache[\/\s]+(\d+\.\d+)', 1)],
    },
    "OpenBSD httpd": {
        "paths": [],
        "headers": {"server": "OpenBSD"},
        "body_patterns": [],
        "version_patterns": [],
    },
    "Lighttpd": {
        "paths": [],
        "headers": {"server": "lighttpd"},
        "body_patterns": [],
        "version_patterns": [(r'lighttpd[\/\s]+(\d+\.\d+)', 1)],
    },
    "Caddy": {
        "paths": [],
        "headers": {"server": "Caddy"},
        "body_patterns": [],
        "version_patterns": [(r'Caddy[\/\s]+(\d+\.\d+)', 1)],
    },
    "HAProxy": {
        "paths": [],
        "headers": {"x-haproxy": ""},
        "body_patterns": [],
        "version_patterns": [],
    },
    "Cloudflare": {
        "paths": [],
        "headers": {"server": "cloudflare"},
        "body_patterns": [],
        "version_patterns": [],
    },
    "Varnish": {
        "paths": [],
        "headers": {"via": "varnish", "x-varnish": ""},
        "body_patterns": [],
        "version_patterns": [],
    },
    "GitLab": {
        "paths": ["/help", "/explore", "/users/sign_in"],
        "headers": {"x-gitlab-": ""},
        "body_patterns": [r'GitLab', r'gitlab'],
        "version_patterns": [(r'GitLab[\/\s]+(\d+\.\d+)', 1)],
    },
    "GitHub Enterprise": {
        "paths": ["/setup", "/stafftools"],
        "headers": {"x-github-": ""},
        "body_patterns": [r'GitHub', r'github\.com'],
        "version_patterns": [],
    },
    "Jenkins": {
        "paths": ["/jenkins/", "/jenkins/login", "/jenkins/script"],
        "headers": {"x-jenkins": ""},
        "body_patterns": [r'Jenkins', r'jenkins'],
        "version_patterns": [(r'Jenkins[\/\s]+(\d+\.\d+)', 1)],
    },
    "Traefik": {
        "paths": [],
        "headers": {"x-traefik": ""},
        "body_patterns": [],
        "version_patterns": [],
    },
    "Grafana": {
        "paths": ["/login", "/dashboard/"],
        "headers": {},
        "body_patterns": [r'Grafana', r'grafana'],
        "version_patterns": [],
    },
    "Prometheus": {
        "paths": ["/targets", "/graph", "/alerts"],
        "headers": {},
        "body_patterns": [r'Prometheus', r'prometheus'],
        "version_patterns": [],
    },
    "Kibana": {
        "paths": ["/app/kibana", "/status"],
        "headers": {"kbn-": ""},
        "body_patterns": [r'Kibana', r'kibana'],
        "version_patterns": [],
    },
    "Jupyter": {
        "paths": ["/api/contents", "/notebooks/", "/tree"],
        "headers": {},
        "body_patterns": [r'Jupyter', r'jupyter'],
        "version_patterns": [],
    },
    "SonarQube": {
        "paths": ["/api/system/status"],
        "headers": {},
        "body_patterns": [r'SonarQube', r'sonarqube'],
        "version_patterns": [],
    },
    "Moodle": {
        "paths": ["/moodle/", "/course/", "/login/index.php"],
        "headers": {},
        "body_patterns": [r'Moodle', r'moodle'],
        "version_patterns": [],
    },
    "Sakai": {
        "paths": ["/portal/", "/sakai/"],
        "headers": {},
        "body_patterns": [r'Sakai', r'sakai'],
        "version_patterns": [],
    },
    "OpenEdX": {
        "paths": ["/login", "/register", "/courses/"],
        "headers": {},
        "body_patterns": [r'OpenEdX', r'openedx', r'edx'],
        "version_patterns": [],
    },
}

class CMSScanner:
    def __init__(self, base_url, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def scan(self, global_timeout=60):
        results = {}
        executor = ThreadPoolExecutor(max_workers=8)
        try:
            futures = {executor.submit(self._check_cms, name, fp): name for name, fp in CMS_FINGERPRINTS.items()}
            for f in as_completed(futures, timeout=global_timeout):
                try:
                    name, data = f.result(timeout=5)
                    if data:
                        results[name] = data
                except Exception:
                    pass
        except TimeoutError:
            pass
        except Exception:
            pass
        finally:
            executor.shutdown(wait=False)
        return results

    def _check_cms(self, cms_name, fingerprints):
        score = 0
        version = ""
        evidence = []
        body_matched = False
        homepage_body = ""
        try:
            r = requests.get(self.base_url, timeout=min(self.timeout, 5), headers={"User-Agent": ua.random}, verify=False)
            if r.status_code == 200:
                homepage_body = r.text
                for header_key, expected_val in fingerprints.get("headers", {}).items():
                    for h_key, h_val in r.headers.items():
                        if h_key.lower() == header_key.lower():
                            if expected_val:
                                if expected_val.lower() in h_val.lower():
                                    score += 25
                                    evidence.append(f"header:{header_key}={expected_val}")
                            else:
                                score += 20
                                evidence.append(f"header:{header_key}=present")
                for pattern in fingerprints.get("body_patterns", []):
                    if re.search(pattern, homepage_body, re.IGNORECASE):
                        score += 20
                        body_matched = True
                        evidence.append(f"body_pattern:{pattern}")
                for pattern, group in fingerprints.get("version_patterns", []):
                    m = re.search(pattern, homepage_body, re.IGNORECASE)
                    if m:
                        version = m.group(group)
                        score += 15
                        evidence.append(f"version:{version}")
        except Exception:
            pass
        for path in fingerprints.get("paths", []):
            url = self.base_url + path
            try:
                r = requests.get(url, timeout=min(self.timeout, 5), headers={"User-Agent": ua.random}, verify=False, allow_redirects=False)
                if r.status_code == 200:
                    if body_matched or any(re.search(p, r.text, re.IGNORECASE) for p in fingerprints.get("body_patterns", [])):
                        score += 10
                        evidence.append(f"path:{path}")
            except Exception:
                continue
        if score >= 40 and body_matched:
            return cms_name, {"detected": True, "confidence": min(score, 100), "version": version, "evidence": evidence[:5]}
        return cms_name, None
