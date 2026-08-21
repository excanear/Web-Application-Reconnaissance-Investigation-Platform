# backend/app/modules/tech_fingerprint.py
import re

import requests

from app import wappalyzer
from app.audit import AuditLog
from app.modules.base import Finding, ReconModule, register_module
from app.ratelimit import CircuitBreaker, RateLimiter
from app.scope import is_in_scope

DEFAULT_RATE_LIMIT = 5.0
DEFAULT_CIRCUIT_BREAKER_THRESHOLD = 5
REQUEST_TIMEOUT = 10

# Project-specific extension, not a native Wappalyzer check type: an
# active path probe for cases needing more precise version detection
# than a passive header/cookie/meta/html/scriptSrc check can offer.
PATH_PROBE_RULES = [
    {
        "category": "cms",
        "name": "WordPress",
        "path": "/CHANGELOG.txt",
        "pattern": r"Version\s+([\d.]+)",
    },
]


@register_module
class TechFingerprintModule(ReconModule):
    name = "tech_fingerprint"
    is_active = True

    def run(self, target: str, context: dict) -> list[Finding]:
        hosts = sorted(context.get("subdomains", set()) | {target})
        scope = context.get("scope")
        audit = context.get("audit")
        limiter = RateLimiter(context.get("rate_limit", DEFAULT_RATE_LIMIT))
        breaker = CircuitBreaker(
            context.get("circuit_breaker_threshold", DEFAULT_CIRCUIT_BREAKER_THRESHOLD)
        )
        technologies = context.get("wappalyzer_technologies")
        if technologies is None:
            technologies = wappalyzer.load_technologies()

        findings: list[Finding] = []
        for index, host in enumerate(hosts):
            if scope is not None and not is_in_scope(host, None, scope):
                findings.append(
                    Finding(type="out_of_scope", value=host, data={"module": self.name})
                )
                continue

            limiter.wait()
            host_findings, reached_host = self._fingerprint_host(host, limiter, audit, technologies)
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

    def _fingerprint_host(
        self, host: str, limiter: RateLimiter, audit: AuditLog | None, technologies: dict
    ) -> tuple[list[Finding], bool]:
        url = f"https://{host}/"
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            if audit is not None:
                audit.record(module=self.name, target=host, outcome=f"error: {exc}", url=url)
            return [], False

        if audit is not None:
            audit.record(module=self.name, target=host, outcome=str(response.status_code), url=url)

        findings = wappalyzer.match_technologies(host, response, technologies=technologies)
        for rule in PATH_PROBE_RULES:
            finding = self._apply_path_probe_rule(host, rule, limiter, audit)
            if finding is not None:
                findings.append(finding)
        return findings, True

    def _apply_path_probe_rule(
        self, host: str, rule: dict, limiter: RateLimiter, audit: AuditLog | None
    ) -> Finding | None:
        limiter.wait()
        probe_url = f"https://{host}{rule['path']}"
        try:
            probe = requests.get(probe_url, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            if audit is not None:
                audit.record(module=self.name, target=host, outcome=f"error: {exc}", url=probe_url)
            return None
        if audit is not None:
            audit.record(module=self.name, target=host, outcome=str(probe.status_code), url=probe_url)
        if probe.status_code != 200:
            return None
        match = re.search(rule["pattern"], probe.text, re.IGNORECASE)
        if not match:
            return None
        version = match.group(1) if match.groups() else None
        return Finding(
            type="technology",
            value=host,
            data={
                "category": rule["category"],
                "name": rule["name"],
                "version": version,
                "confidence": "high" if version else "medium",
                "source": "path_probe",
            },
        )
