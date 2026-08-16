import re

import requests

from app.modules.base import Finding, ReconModule, register_module

# Seed ruleset -- extensible without touching the engine below. Each rule:
# category, name, match_type (header/cookie/meta_generator/path_probe),
# and a pattern whose first capture group (if any) is the version.
FINGERPRINT_RULES = [
    {
        "category": "web_server",
        "name": "nginx",
        "match_type": "header",
        "header": "Server",
        "pattern": r"nginx/?([\d.]+)?",
    },
    {
        "category": "web_server",
        "name": "Apache",
        "match_type": "header",
        "header": "Server",
        "pattern": r"Apache/?([\d.]+)?",
    },
    {
        "category": "backend",
        "name": "PHP",
        "match_type": "header",
        "header": "X-Powered-By",
        "pattern": r"PHP/?([\d.]+)?",
    },
    {
        "category": "backend",
        "name": "ASP.NET",
        "match_type": "header",
        "header": "X-AspNet-Version",
        "pattern": r"([\d.]+)",
    },
    {"category": "backend", "name": "PHP", "match_type": "cookie", "cookie": "PHPSESSID"},
    {"category": "backend", "name": "Java", "match_type": "cookie", "cookie": "JSESSIONID"},
    {
        "category": "cms",
        "name": "WordPress",
        "match_type": "meta_generator",
        "pattern": r"WordPress\s*([\d.]+)?",
    },
    {
        "category": "cms",
        "name": "WordPress",
        "match_type": "path_probe",
        "path": "/CHANGELOG.txt",
        "pattern": r"Version\s+([\d.]+)",
    },
]

REQUEST_TIMEOUT = 10


@register_module
class TechFingerprintModule(ReconModule):
    name = "tech_fingerprint"

    def run(self, target: str, context: dict) -> list[Finding]:
        hosts = context.get("subdomains", set()) | {target}
        findings: list[Finding] = []
        for host in sorted(hosts):
            findings.extend(self._fingerprint_host(host))
        return findings

    def _fingerprint_host(self, host: str) -> list[Finding]:
        try:
            response = requests.get(f"https://{host}/", timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            return []

        findings = []
        for rule in FINGERPRINT_RULES:
            finding = self._apply_rule(host, rule, response)
            if finding is not None:
                findings.append(finding)
        return findings

    def _apply_rule(self, host: str, rule: dict, response) -> Finding | None:
        if rule["match_type"] == "header":
            value = response.headers.get(rule["header"], "")
            match = re.search(rule["pattern"], value, re.IGNORECASE)
            if not match:
                return None
            return self._finding(host, rule, match, source="header")

        if rule["match_type"] == "cookie":
            if rule["cookie"] not in response.cookies:
                return None
            return self._finding(host, rule, match=None, source="cookie")

        if rule["match_type"] == "meta_generator":
            meta_match = re.search(
                r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
                response.text,
                re.IGNORECASE,
            )
            if meta_match is None:
                return None
            match = re.search(rule["pattern"], meta_match.group(1), re.IGNORECASE)
            if not match:
                return None
            return self._finding(host, rule, match, source="meta_generator")

        if rule["match_type"] == "path_probe":
            try:
                probe = requests.get(f"https://{host}{rule['path']}", timeout=REQUEST_TIMEOUT)
            except requests.RequestException:
                return None
            if probe.status_code != 200:
                return None
            match = re.search(rule["pattern"], probe.text, re.IGNORECASE)
            if not match:
                return None
            return self._finding(host, rule, match, source="path_probe")

        return None

    @staticmethod
    def _finding(host: str, rule: dict, match, source: str) -> Finding:
        version = match.group(1) if match and match.groups() else None
        return Finding(
            type="technology",
            value=host,
            data={
                "category": rule["category"],
                "name": rule["name"],
                "version": version,
                "confidence": "high" if version else "medium",
                "source": source,
            },
        )
