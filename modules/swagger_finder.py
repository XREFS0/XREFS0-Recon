import requests
import re
from urllib.parse import urljoin
from fake_useragent import UserAgent

ua = UserAgent()

SWAGGER_PATHS = [
    "/api/docs", "/api/swagger", "/api/swagger/", "/swagger", "/swagger/",
    "/swagger/ui", "/swagger/index.html", "/swagger/v1", "/swagger/v2",
    "/swagger.json", "/swagger.yaml", "/swagger.yml",
    "/api/swagger.json", "/api/swagger.yaml", "/api/swagger.yml",
    "/api-docs", "/api-docs/", "/api/documentation",
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/docs", "/docs/", "/redoc", "/redoc/",
    "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
    "/v1/api-docs", "/v2/api-docs",
    "/api/v1/swagger.json", "/api/v2/swagger.json",
    "/api/v1/api-docs", "/api/v2/api-docs",
    "/graphql", "/graphql/",
    "/graphiql", "/graphiql/",
    "/playground", "/playground/",
    "/api/graphql", "/api/graphql/",
]

GRAPHQL_QUERIES = [
    '{"query":"{__schema{types{name}}}"}',
    '{"query":"{__schema{queryType{name}}}"}',
    '{"query":"{__typename}"}',
]

class SwaggerFinder:
    def __init__(self, base_url, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def find_swagger(self):
        results = []
        for path in SWAGGER_PATHS:
            url = self.base_url + path
            try:
                r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random}, verify=False, allow_redirects=True)
                if r.status_code == 200:
                    content = r.text.lower()
                    if any(k in content for k in ["swagger", "openapi", "graphql", "schema", "specification"]):
                        results.append({
                            "url": url,
                            "type": self._classify(path, content),
                            "status": r.status_code,
                        })
                    elif path.endswith((".json", ".yaml", ".yml")):
                        results.append({
                            "url": url,
                            "type": "openapi_spec",
                            "status": r.status_code,
                        })
            except Exception:
                continue
        return results

    def check_graphql_introspection(self):
        results = []
        graphql_urls = [
            self.base_url + "/graphql",
            self.base_url + "/graphql/",
            self.base_url + "/api/graphql",
            self.base_url + "/graphiql",
            self.base_url + "/playground",
        ]
        for url in graphql_urls:
            for query in GRAPHQL_QUERIES:
                try:
                    r = requests.post(url, json={"query": query}, timeout=self.timeout,
                                      headers={"User-Agent": ua.random, "Content-Type": "application/json"},
                                      verify=False)
                    if r.status_code == 200 and ("__schema" in r.text or "__typename" in r.text):
                        results.append({
                            "url": url,
                            "introspection": True,
                            "data_preview": r.text[:500],
                        })
                        break
                except Exception:
                    continue
        return results

    def _classify(self, path, content):
        if "graphql" in path.lower() or "graphiql" in path.lower() or "playground" in path.lower():
            return "graphql"
        if content and ("swagger" in content or "openapi" in content or "specification" in content):
            return "swagger_openapi"
        return "api_docs"
