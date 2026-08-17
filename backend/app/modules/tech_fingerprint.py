import re

import requests

from app.modules.base import Finding, ReconModule, register_module
from app.ratelimit import CircuitBreaker, RateLimiter
from app.scope import is_in_scope

DEFAULT_RATE_LIMIT = 5.0
DEFAULT_CIRCUIT_BREAKER_THRESHOLD = 5

# Seed ruleset -- extensible without touching the engine below. Each rule:
# category, name, match_type (header/cookie/meta_generator/html_regex/
# path_probe), and a pattern whose first capture group (if any) is the
# version. Presence-only rules (no version ever exposed) use pattern r".+".
FINGERPRINT_RULES = [
    # -- Web servers --
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
        "category": "web_server",
        "name": "Microsoft-IIS",
        "match_type": "header",
        "header": "Server",
        "pattern": r"Microsoft-IIS/?([\d.]+)?",
    },
    {
        "category": "web_server",
        "name": "Tomcat",
        "match_type": "header",
        "header": "Server",
        "pattern": r"(?:Apache-Coyote|Tomcat)/?([\d.]+)?",
    },
    # -- CDN / WAF --
    {
        "category": "cdn_waf",
        "name": "Cloudflare",
        "match_type": "header",
        "header": "Server",
        "pattern": r"cloudflare",
    },
    {
        "category": "cdn_waf",
        "name": "Akamai",
        "match_type": "header",
        "header": "Server",
        "pattern": r"AkamaiGHost",
    },
    {
        "category": "cdn_waf",
        "name": "Varnish",
        "match_type": "header",
        "header": "Via",
        "pattern": r"varnish",
    },
    {
        "category": "cdn_waf",
        "name": "AWS CloudFront",
        "match_type": "header",
        "header": "Via",
        "pattern": r"CloudFront",
    },
    {
        "category": "cdn_waf",
        "name": "Fastly",
        "match_type": "header",
        "header": "X-Served-By",
        "pattern": r".+",
    },
    # -- Backend language / framework --
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
    {
        "category": "backend",
        "name": "Express",
        "match_type": "header",
        "header": "X-Powered-By",
        "pattern": r"Express",
    },
    {
        "category": "backend",
        "name": "Werkzeug/Flask",
        "match_type": "header",
        "header": "Server",
        "pattern": r"Werkzeug/?([\d.]+)?",
    },
    {
        "category": "backend",
        "name": "Ruby on Rails",
        "match_type": "header",
        "header": "X-Runtime",
        "pattern": r".+",
    },
    {"category": "backend", "name": "PHP", "match_type": "cookie", "cookie": "PHPSESSID"},
    {"category": "backend", "name": "Java", "match_type": "cookie", "cookie": "JSESSIONID"},
    {"category": "backend", "name": "Laravel", "match_type": "cookie", "cookie": "laravel_session"},
    {"category": "backend", "name": "Django", "match_type": "cookie", "cookie": "csrftoken"},
    # -- CMS --
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
    {
        "category": "cms",
        "name": "Drupal",
        "match_type": "meta_generator",
        "pattern": r"Drupal\s*([\d.]+)?",
    },
    {
        "category": "cms",
        "name": "Joomla",
        "match_type": "meta_generator",
        "pattern": r"Joomla!?\s*([\d.]+)?",
    },
    {
        "category": "cms",
        "name": "Shopify",
        "match_type": "header",
        "header": "X-Shopify-Stage",
        "pattern": r".+",
    },
    # -- Frontend / JS frameworks (body content) --
    {
        "category": "frontend",
        "name": "Angular",
        "match_type": "html_regex",
        "pattern": r'ng-version="([\d.]+)"',
    },
    {
        "category": "frontend",
        "name": "React",
        "match_type": "html_regex",
        "pattern": r"data-reactroot|react-dom",
    },
    {
        "category": "frontend",
        "name": "Vue.js",
        "match_type": "html_regex",
        "pattern": r"data-v-app|__vue__|Vue\.js",
    },
    {
        "category": "frontend",
        "name": "Next.js",
        "match_type": "html_regex",
        "pattern": r"__NEXT_DATA__",
    },
    {
        "category": "frontend",
        "name": "jQuery",
        "match_type": "html_regex",
        "pattern": r"jquery[.-]?([\d.]+)?(?:\.min)?\.js",
    },
    {
        "category": "frontend",
        "name": "Bootstrap",
        "match_type": "html_regex",
        "pattern": r"bootstrap[.-]?([\d.]+)?(?:\.min)?\.(?:css|js)",
    },
]

REQUEST_TIMEOUT = 10


@register_module
class TechFingerprintModule(ReconModule):
    name = "tech_fingerprint"
    is_active = True

    def run(self, target: str, context: dict) -> list[Finding]:
        hosts = sorted(context.get("subdomains", set()) | {target})
        scope = context.get("scope")
        limiter = RateLimiter(context.get("rate_limit", DEFAULT_RATE_LIMIT))
        breaker = CircuitBreaker(
            context.get("circuit_breaker_threshold", DEFAULT_CIRCUIT_BREAKER_THRESHOLD)
        )

        findings: list[Finding] = []
        for index, host in enumerate(hosts):
            if scope is not None and not is_in_scope(host, None, scope):
                findings.append(
                    Finding(type="out_of_scope", value=host, data={"module": self.name})
                )
                continue

            limiter.wait()
            host_findings, reached_host = self._fingerprint_host(host, limiter)
            findings.extend(host_findings)

            if reached_host:
                breaker.record_success()
                continue

            if breaker.record_failure():
                findings.append(
                    Finding(
                        type="circuit_breaker_tripped",
                        value=host,
                        data={"module": self.name, "skipped_hosts": len(hosts) - index - 1},
                    )
                )
                break
        return findings

    def _fingerprint_host(self, host: str, limiter: RateLimiter) -> tuple[list[Finding], bool]:
        try:
            response = requests.get(f"https://{host}/", timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            return [], False

        findings = []
        for rule in FINGERPRINT_RULES:
            finding = self._apply_rule(host, rule, response, limiter)
            if finding is not None:
                findings.append(finding)
        return findings, True

    def _apply_rule(self, host: str, rule: dict, response, limiter: RateLimiter) -> Finding | None:
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

        if rule["match_type"] == "html_regex":
            match = re.search(rule["pattern"], response.text, re.IGNORECASE)
            if not match:
                return None
            return self._finding(host, rule, match, source="html_regex")

        if rule["match_type"] == "path_probe":
            limiter.wait()
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
