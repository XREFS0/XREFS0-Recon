import re
import hashlib
from fake_useragent import UserAgent

ua = UserAgent()

TECH_PATTERNS = {
    "WordPress": [r'wp-content', r'wp-includes', r'wp-json', r'WordPress'],
    "Joomla": [r'joomla', r'com_content', r'com_modules'],
    "Drupal": [r'drupal', r'sites/default', r'Drupal'],
    "Laravel": [r'laravel', r'_token'],
    "Django": [r'django', r'csrfmiddlewaretoken', r'__admin'],
    "React": [r'react', r'react-dom', r'__NEXT_DATA__', r'next/static'],
    "Vue.js": [r'vue', r'__VUE__', r'vuejs'],
    "Angular": [r'angular', r'ng-version', r'ng-app'],
    "Next.js": [r'__NEXT_DATA__', r'next/static', r'_next'],
    "Nuxt.js": [r'__NUXT__', r'nuxt'],
    "jQuery": [r'jquery', r'jQuery'],
    "Bootstrap": [r'bootstrap', r'\.min\.css'],
    "Tailwind": [r'tailwind', r'h-4\b', r'w-4\b'],
    "Nginx": [r'nginx'],
    "Apache": [r'apache', r'Apache'],
    "IIS": [r'iis', r'IIS', r'asp\.net'],
    "Caddy": [r'caddy', r'Caddy'],
    "Tomcat": [r'tomcat', r'Tomcat'],
    "Next.js": [r'__NEXT_DATA__', r'next/static', r'_next'],
    "Vercel": [r'vercel', r'x-vercel', r'Vercel'],
    "Node.js": [r'node\.js', r'Node\.js', r'express'],
    "Cloudflare": [r'cloudflare', r'__cfduid'],
    "Google Analytics": [r'google-analytics', r'gtag', r'ga\.js'],
    "Facebook Pixel": [r'fbq', r'connect\.facebook', r'pixel'],
    "Hotjar": [r'hotjar', r'hj\('],
    "MySQL": [r'mysql', r'MySQL'],
    "PHP": [r'php', r'PHP'],
    "Python": [r'python', r'django', r'flask'],
    "Ruby": [r'ruby', r'rails', r'Rails'],
    "Shopify": [r'shopify', r'myshopify'],
    "Magento": [r'magento', r'Mage\.'],
    "Wix": [r'wix', r'Wix\.'],
}

class TechDetector:
    def __init__(self):
        pass

    def detect(self, url, html, headers):
        detected = {}
        combined = str(headers).lower() + " " + html.lower()
        for tech, patterns in TECH_PATTERNS.items():
            matches = []
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    matches.append(pattern)
            if matches:
                detected[tech] = matches
        return detected
