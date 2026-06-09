import dns.resolver
import requests
from fake_useragent import UserAgent

ua = UserAgent()

FINGERPRINTS = {
    "aws-s3": {
        "cname": [".s3.amazonaws.com", ".s3-website", "s3-"],
        "response": "NoSuchBucket",
    },
    "aws-cloudfront": {
        "cname": [".cloudfront.net"],
        "response": "X-Error: No such distribution",
    },
    "azure": {
        "cname": [".azureedge.net", ".azurewebsites.net", ".trafficmanager.net", ".azure-api.net", ".azurecontainer.io"],
        "response": "404 Not Found",
    },
    "azure-blob": {
        "cname": [".blob.core.windows.net"],
        "response": "The specified blob does not exist",
    },
    "github-pages": {
        "cname": [".github.io"],
        "response": "There isn't a GitHub Pages site here",
    },
    "heroku": {
        "cname": [".herokuapp.com"],
        "response": "There's nothing here, yet",
    },
    "heroku-2": {
        "cname": [".herokuapp.com"],
        "response": "No such app",
    },
    "shopify": {
        "cname": [".myshopify.com"],
        "response": "Sorry, this shop is currently unavailable",
    },
    "wordpress": {
        "cname": [".wordpress.com"],
        "response": "Do you want to register",
    },
    "fastly": {
        "cname": [".fastly.net", ".global.prod.fastly.net", ".fastlylb.net"],
        "response": "Fastly error: unknown domain",
    },
    "zendesk": {
        "cname": [".zendesk.com"],
        "response": "Help Center Closed",
    },
    "bitbucket": {
        "cname": [".bitbucket.io"],
        "response": "This bucket has not been activated yet",
    },
    "campaignmonitor": {
        "cname": [".createsend.com"],
        "response": "Trying to access your account",
    },
    "cargo": {
        "cname": [".cargocollective.com"],
        "response": "404 Not Found",
    },
    "fly.io": {
        "cname": [".fly.dev", ".fly.io"],
        "response": "404 Not Found",
    },
    "ghost": {
        "cname": [".ghost.io"],
        "response": "The thing you were looking for is no longer here",
    },
    "hatch": {
        "cname": [".hatchboxapp.com"],
        "response": "Application not found",
    },
    "helpjuice": {
        "cname": [".helpjuice.com"],
        "response": "We could not find what you're looking for",
    },
    "helpscout": {
        "cname": [".helpscoutdocs.com"],
        "response": "No help article found",
    },
    "intercom": {
        "cname": [".custom.intercom.help"],
        "response": "This page is out of date",
    },
    "keyhelp": {
        "cname": [".keyhelp.io"],
        "response": "No such app",
    },
    "kinsta": {
        "cname": [".kinsta.cloud"],
        "response": "No Site Found",
    },
    "launchrock": {
        "cname": [".launchrock.com"],
        "response": "We don't have a page for that",
    },
    "mashery": {
        "cname": [".mashery.com"],
        "response": "404 Not Found",
    },
    "netlify": {
        "cname": [".netlify.app", ".netlify.com"],
        "response": "Not Found - Request ID:",
    },
    "pantheon": {
        "cname": [".pantheonsite.io"],
        "response": "The gods are angry",
    },
    "pingdom": {
        "cname": [".pingdom.com"],
        "response": "Please check the name",
    },
    "readme": {
        "cname": [".readme.io"],
        "response": "Project doesnt exist... yet",
    },
    "sendgrid": {
        "cname": [".sendgrid.net"],
        "response": "No such app",
    },
    "smugmug": {
        "cname": [".smugmug.com"],
        "response": "No Such Page",
    },
    "surge": {
        "cname": [".surge.sh"],
        "response": "project not found",
    },
    "teamwork": {
        "cname": [".teamwork.com"],
        "response": "This is not the page you're looking for",
    },
    "tictail": {
        "cname": [".tictail.com"],
        "response": "Page not found",
    },
    "tumblr": {
        "cname": [".tumblr.com"],
        "response": "There's nothing here",
    },
    "unbounce": {
        "cname": [".unbouncepages.com"],
        "response": "The requested resource was not found",
    },
    "uservoice": {
        "cname": [".uservoice.com"],
        "response": "This UserVoice instance is not currently accepting new domains",
    },
    "webflow": {
        "cname": [".webflow.io"],
        "response": "The page you are looking for doesn't exist",
    },
    "wishpond": {
        "cname": [".wishpond.com"],
        "response": "No Site Found",
    },
    "aftership": {
        "cname": [".aftership.com"],
        "response": "Oops! That page doesn't exist",
    },
    "aha": {
        "cname": [".aha.io"],
        "response": "There is no Aha! account at this domain",
    },
    "aws-elb": {
        "cname": [".elb.amazonaws.com"],
        "response": "404 Not Found",
    },
    "bigcartel": {
        "cname": [".bigcartel.com"],
        "response": "The page you were looking for doesn't exist",
    },
    "brightcove": {
        "cname": [".brightcove.com"],
        "response": "Page not found",
    },
    "canny": {
        "cname": [".canny.io"],
        "response": "There is no such company",
    },
    "clickfunnels": {
        "cname": [".clickfunnels.com"],
        "response": "The page you're looking for is not here",
    },
    "cloudfront": {
        "cname": [".cloudfront.net"],
        "response": "The request could not be satisfied",
    },
    "disqus": {
        "cname": [".disqus.com"],
        "response": "We don't have a page for that",
    },
    "eventbrite": {
        "cname": [".eventbrite.com"],
        "response": "The page you're looking for doesn't exist",
    },
    "fibery": {
        "cname": [".fibery.io"],
        "response": "Not found",
    },
    "flipkart": {
        "cname": [".flipkart.com"],
        "response": "404 - Page not found",
    },
    "framer": {
        "cname": [".framer.app"],
        "response": "404 Not Found",
    },
    "freshdesk": {
        "cname": [".freshdesk.com"],
        "response": "This support portal is no longer available",
    },
    "gather": {
        "cname": [".gather.town"],
        "response": "This page is unavailable",
    },
    "getresponse": {
        "cname": [".getresponse.com"],
        "response": "The site is not found",
    },
    "gitea": {
        "cname": [".gitea.io"],
        "response": "The page you're looking for is not there",
    },
    "gitbook": {
        "cname": [".gitbook.io"],
        "response": "The page you're looking for doesn't exist",
    },
    "glitch": {
        "cname": [".glitch.me"],
        "response": "Page not found",
    },
    "google-cloud": {
        "cname": ["c.storage.googleapis.com"],
        "response": "The specified bucket does not exist",
    },
    "google-sites": {
        "cname": [".googlepages.com"],
        "response": "Not found",
    },
    "hatena": {
        "cname": [".hatenablog.com"],
        "response": "404 Not Found",
    },
    "helpshift": {
        "cname": [".helpshift.com"],
        "response": "The page you're looking for isn't available",
    },
    "hubspot": {
        "cname": [".hubspot.com"],
        "response": "No such domain",
    },
    "instapage": {
        "cname": [".instapage.com"],
        "response": "The page you were looking for doesn't exist",
    },
    "ipage": {
        "cname": [".ipage.com"],
        "response": "404 Not Found",
    },
    "kajabi": {
        "cname": [".kajabi.com"],
        "response": "The page you're looking for doesn't exist",
    },
    "knightlab": {
        "cname": [".knightlab.com"],
        "response": "There's nothing here",
    },
    "launchdarkly": {
        "cname": [".launchdarkly.com"],
        "response": "This page is not available",
    },
    "lever": {
        "cname": [".lever.co"],
        "response": "This page is not available",
    },
    "linktree": {
        "cname": [".linktr.ee"],
        "response": "The page you're looking for doesn't exist",
    },
    "loggly": {
        "cname": [".loggly.com"],
        "response": "Page not found",
    },
    "microsoft-azure": {
        "cname": [".azure-mobile.net", ".cloudapp.net", ".azurewebsites.net"],
        "response": "404 Not Found",
    },
    "mighty": {
        "cname": [".mighty.com"],
        "response": "The page you're looking for doesn't exist",
    },
    "newsletter": {
        "cname": [".newsletter.com"],
        "response": "The domain you're looking for is not here",
    },
    "notion": {
        "cname": [".notion.site"],
        "response": "We couldn't find the page you're looking for",
    },
    "npm": {
        "cname": [".npmjs.com"],
        "response": "Page not found",
    },
    "orbit": {
        "cname": [".orbit.chat"],
        "response": "The page you're looking for isn't available",
    },
    "outseta": {
        "cname": [".outseta.com"],
        "response": "The page you're looking for doesn't exist",
    },
    "pagerduty": {
        "cname": [".pagerduty.com"],
        "response": "No such domain",
    },
    "pantheon-2": {
        "cname": [".pantheon.io"],
        "response": "The page you are looking for is not here",
    },
    "podbean": {
        "cname": [".podbean.com"],
        "response": "404 Not Found",
    },
    "replit": {
        "cname": [".repl.co"],
        "response": "The page you're looking for doesn't exist",
    },
    "simplebooklet": {
        "cname": [".simplebooklet.com"],
        "response": "Page not found",
    },
    "squarespace": {
        "cname": [".squarespace.com"],
        "response": "No site found",
    },
    "strikingly": {
        "cname": [".strikingly.com"],
        "response": "The page you're looking for doesn't exist",
    },
    "stripe": {
        "cname": [".stripe.com"],
        "response": "The page you're looking for doesn't exist",
    },
    "surge-2": {
        "cname": [".surge.sh"],
        "response": "There is no such page",
    },
    "teachable": {
        "cname": [".teachable.com"],
        "response": "The page you're looking for doesn't exist",
    },
    "teamwork-2": {
        "cname": [".teamwork.com"],
        "response": "Page not found",
    },
    "thinkific": {
        "cname": [".thinkific.com"],
        "response": "The page you're looking for doesn't exist",
    },
    "tilda": {
        "cname": [".tilda.ws"],
        "response": "Page not found",
    },
    "typeform": {
        "cname": [".typeform.com"],
        "response": "Page not found",
    },
    "udemy": {
        "cname": [".udemy.com"],
        "response": "The page you're looking for doesn't exist",
    },
    "weebly-2": {
        "cname": [".weebly.com"],
        "response": "There is no page here",
    },
    "wildapricot": {
        "cname": [".wildapricot.com"],
        "response": "Page not found",
    },
    "wix-2": {
        "cname": [".wixsite.com", ".wix.com"],
        "response": "Page not found",
    },
    "wordpress-2": {
        "cname": [".wordpress.com"],
        "response": "The page you're looking for doesn't exist",
    },
    "worksites": {
        "cname": [".worksites.com"],
        "response": "The page you're looking for doesn't exist",
    },
    "xano": {
        "cname": [".xano.com"],
        "response": "The page you're looking for doesn't exist",
    },
    "zendesk-2": {
        "cname": [".zendesk.com"],
        "response": "The page you're looking for doesn't exist",
    },
}

class TakeoverChecker:
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def check(self, hostname):
        result = {"hostname": hostname, "vulnerable": False, "service": "", "details": ""}
        cnames = self._get_cnames(hostname)
        if not cnames:
            return result
        for cname in cnames:
            for service, fingerprint in FINGERPRINTS.items():
                for pattern in fingerprint["cname"]:
                    if pattern in cname.lower():
                        if self._verify_takeover(hostname, fingerprint["response"]):
                            result["vulnerable"] = True
                            result["service"] = service
                            result["details"] = f"CNAME: {cname}, Service: {service}"
                            return result
        return result

    def _get_cnames(self, hostname):
        try:
            answers = self.resolver.resolve(hostname, "CNAME", lifetime=self.timeout)
            return [str(r).rstrip(".") for r in answers]
        except Exception:
            return []

    def _verify_takeover(self, hostname, expected_response):
        try:
            for scheme in ["https", "http"]:
                r = requests.get(
                    f"{scheme}://{hostname}",
                    timeout=self.timeout,
                    headers={"User-Agent": ua.random},
                    verify=False,
                )
                if expected_response.lower() in r.text.lower():
                    return True
        except Exception:
            pass
        return False
