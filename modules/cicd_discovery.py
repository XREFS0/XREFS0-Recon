import requests
from urllib.parse import urljoin
from fake_useragent import UserAgent

ua = UserAgent()

CI_CD_PATHS = [
    "/.gitlab-ci.yml",
    "/.github/workflows",
    "/.github/workflows/main.yml",
    "/.github/workflows/deploy.yml",
    "/.circleci/config.yml",
    "/Jenkinsfile",
    "/.travis.yml",
    "/.drone.yml",
    "/bitbucket-pipelines.yml",
    "/.buildkite/pipeline.yml",
    "/.semaphore/semaphore.yml",
    "/.woodpecker.yml",
    "/.gitea/workflows",
    "/.githooks",
    "/Dockerfile",
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/.dockerignore",
    "/ansible.cfg",
    "/ansible/",
    "/ansible/playbook.yml",
    "/ansible/playbook.yaml",
    "/ansible/inventory",
    "/ansible/roles",
    "/terraform/",
    "/terraform/main.tf",
    "/terraform/variables.tf",
    "/terraform/outputs.tf",
    "/terraform/terraform.tfvars",
    "/.terraform/",
    "/.terraform.lock.hcl",
    "/Puppetfile",
    "/manifests/",
    "/chef/",
    "/chef/solo.rb",
    "/Berksfile",
    "/salt/",
    "/salt/top.sls",
    "/kubernetes/",
    "/k8s/",
    "/k8s/deployment.yaml",
    "/k8s/service.yaml",
    "/helm/",
    "/helm/Chart.yaml",
    "/helm/values.yaml",
    "/.helmignore",
    "/kustomization.yaml",
    "/kustomization.yml",
    "/deployment.yaml",
    "/service.yaml",
    "/ingress.yaml",
    "/configmap.yaml",
    "/secret.yaml",
    "/namespace.yaml",
    "/.kube/",
    "/.kube/config",
    "/.docker/config.json",
    "/Makefile",
    "/.env.example",
    "/.env",
    "/.npmrc",
    "/.yarnrc",
    "/.pypirc",
    "/.gemrc",
    "/composer.json",
    "/package.json",
    "/requirements.txt",
    "/Gemfile",
    "/Pipfile",
    "/setup.py",
    "/Procfile",
    "/app.json",
    "/scalingo.json",
    "/.ebextensions/",
    "/.elasticbeanstalk/",
    "/appspec.yml",
    "/serverless.yml",
    "/serverless.yaml",
    "/serverless.json",
    "/.chalice/",
    "/zappa_settings.json",
    "/sam.yml",
    "/sam.yaml",
    "/template.yml",
    "/template.yaml",
]

class CICDDiscovery:
    def __init__(self, base_url, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def find(self, max_workers=20):
        results = []
        for path in CI_CD_PATHS:
            url = self.base_url + path
            try:
                r = requests.get(url, timeout=self.timeout, headers={"User-Agent": ua.random}, verify=False, allow_redirects=False)
                if r.status_code not in [404, 410]:
                    results.append({
                        "url": url,
                        "status": r.status_code,
                        "size": len(r.content),
                        "type": self._classify(path),
                    })
            except Exception:
                continue
        return results

    def _classify(self, path):
        path_lower = path.lower()
        if "gitlab" in path_lower: return "gitlab_ci"
        if "github" in path_lower: return "github_actions"
        if "circleci" in path_lower: return "circleci"
        if "jenkins" in path_lower: return "jenkins"
        if "travis" in path_lower: return "travis_ci"
        if "docker" in path_lower: return "docker"
        if "docker-compose" in path_lower: return "docker_compose"
        if "ansible" in path_lower: return "ansible"
        if "terraform" in path_lower: return "terraform"
        if "kubernetes" in path_lower or "k8s" in path_lower or "kube" in path_lower: return "kubernetes"
        if "helm" in path_lower: return "helm"
        if "kustomize" in path_lower: return "kustomize"
        if "deployment" in path_lower or "service" in path_lower or "ingress" in path_lower: return "kubernetes_manifest"
        if "env" in path_lower: return "env_file"
        if "makefile" in path_lower: return "makefile"
        if "serverless" in path_lower: return "serverless"
        if "sam" in path_lower: return "aws_sam"
        if "chalice" in path_lower: return "aws_chalice"
        return "ci_cd"
