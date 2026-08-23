# backend/app/modules/tech_fingerprint.py
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin

import requests

from app import wappalyzer
from app.audit import AuditLog
from app.modules.base import Finding, ReconModule, prioritized_hosts, register_module
from app.ratelimit import CircuitBreaker, RateLimiter
from app.scope import is_in_scope

DEFAULT_RATE_LIMIT = 5.0
DEFAULT_CIRCUIT_BREAKER_THRESHOLD = 5
DEFAULT_MAX_WORKERS = 1
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
        hosts = prioritized_hosts(context, target)
        scope = context.get("scope")
        audit = context.get("audit")
        max_workers = context.get("max_workers", DEFAULT_MAX_WORKERS)
        limiter = RateLimiter(context.get("rate_limit", DEFAULT_RATE_LIMIT))
        breaker = CircuitBreaker(
            context.get("circuit_breaker_threshold", DEFAULT_CIRCUIT_BREAKER_THRESHOLD)
        )
        technologies = context.get("wappalyzer_technologies")
        if technologies is None:
            technologies = wappalyzer.load_technologies()
        wappalyzer.load_categories()

        findings: list[Finding] = []

        for batch_start in range(0, len(hosts), max_workers):
            batch = hosts[batch_start:batch_start + max_workers]
            in_scope_batch = [
                host for host in batch if scope is None or is_in_scope(host, None, scope)
            ]
            for host in batch:
                if host not in in_scope_batch:
                    findings.append(
                        Finding(type="out_of_scope", value=host, data={"module": self.name})
                    )

            if not in_scope_batch:
                continue

            with ThreadPoolExecutor(max_workers=len(in_scope_batch)) as executor:
                results = list(
                    executor.map(
                        lambda host: self._fingerprint_host(host, limiter, audit, technologies),
                        in_scope_batch,
                    )
                )

            breaker_tripped = False
            for offset, host in enumerate(batch):
                if host not in in_scope_batch:
                    continue
                index = batch_start + offset
                host_findings, reached_host = results[in_scope_batch.index(host)]
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
                    breaker_tripped = True
                    break

            if breaker_tripped:
                break
        return findings

    def _fingerprint_host(
        self, host: str, limiter: RateLimiter, audit: AuditLog | None, technologies: dict
    ) -> tuple[list[Finding], bool]:
        limiter.wait()
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
        for finding in findings:
            self._backfill_version_from_script_content(finding, host, limiter, audit)
        for rule in PATH_PROBE_RULES:
            finding = self._apply_path_probe_rule(host, rule, limiter, audit)
            if finding is not None:
                findings.append(finding)
        return findings, True

    def _backfill_version_from_script_content(
        self, finding: Finding, host: str, limiter: RateLimiter, audit: AuditLog | None
    ) -> None:
        """A scriptSrc match with no version (e.g. a self-hosted vendor
        script whose URL carries no version number) can often still be
        pinned down by fetching that exact script and reading its own
        version banner comment -- see
        wappalyzer.extract_version_from_script_banner. Updates `finding`
        in place; leaves it untouched on any failure."""
        script_src = finding.data.get("script_src")
        if finding.data.get("version") is not None or not script_src:
            return

        script_url = urljoin(f"https://{host}/", script_src)
        limiter.wait()
        try:
            # Range asks the server to send only the banner-sized prefix
            # of what can be a multi-hundred-KB minified bundle -- a
            # server that ignores it just returns the full file (200),
            # which is still handled fine since only the first bytes of
            # .text are ever read.
            response = requests.get(
                script_url, headers={"Range": "bytes=0-4095"}, timeout=REQUEST_TIMEOUT
            )
        except requests.RequestException as exc:
            if audit is not None:
                audit.record(
                    module=self.name, target=host, outcome=f"error: {exc}", url=script_url
                )
            return

        if audit is not None:
            audit.record(
                module=self.name, target=host, outcome=str(response.status_code), url=script_url
            )
        if response.status_code >= 400:
            return

        version = wappalyzer.extract_version_from_script_banner(
            finding.data["name"], response.text or ""
        )
        if version:
            finding.data["version"] = version
            finding.data["confidence"] = "high"

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
