import time

import requests

from app.audit import AuditLog
from app.config import settings
from app.epss import fetch_epss
from app.modules.base import Finding, ReconModule, register_module
from app.ratelimit import CircuitBreaker
from app.translate import translate_en_to_pt

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 30

# NVD rate limits: 5 req/30s unauthenticated, 50 req/30s with an API key.
UNAUTHENTICATED_DELAY_SECONDS = 6.0
AUTHENTICATED_DELAY_SECONDS = 0.6

DEFAULT_RATE_LIMIT = 5.0
DEFAULT_CIRCUIT_BREAKER_THRESHOLD = 5

CVSS_METRIC_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def _parse_version(version: str) -> tuple[int, ...]:
    parts = []
    for chunk in version.split("."):
        digits = "".join(ch for ch in chunk if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _version_in_range(version: str, start_inc, start_exc, end_inc, end_exc) -> bool:
    v = _parse_version(version)
    if start_inc is not None and v < _parse_version(start_inc):
        return False
    if start_exc is not None and v <= _parse_version(start_exc):
        return False
    if end_inc is not None and v > _parse_version(end_inc):
        return False
    if end_exc is not None and v >= _parse_version(end_exc):
        return False
    return True


# Some fingerprinted display names don't match their CPE product slug --
# e.g. our "Apache" web-server rule means Apache HTTP Server, whose CPE
# product is "http_server", not "apache". Matching the raw display name
# against the *vendor* field (as a whole-criteria substring search does)
# spuriously matches every unrelated product from the same vendor -- for
# "apache" that means Log4j, Tomcat, Struts, ActiveMQ, etc. all showing up
# as "suspected" CVEs for the web server alone.
_CPE_PRODUCT_ALIASES = {"apache": "httpserver"}  # matched against a dash/underscore-stripped product field


def _cve_matches_version(cve: dict, name: str, version: str) -> bool:
    needle = name.lower().replace(" ", "").replace("-", "").replace("_", "")
    needle = _CPE_PRODUCT_ALIASES.get(needle, needle)
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                parts = match.get("criteria", "").split(":")
                # cpe:2.3:a:vendor:product:version:... -- match against the
                # product field specifically, not the whole criteria string,
                # so a shared vendor never causes a false match on its own.
                product = parts[4].lower().replace("-", "").replace("_", "") if len(parts) > 4 else ""
                if product != needle:
                    continue

                start_inc = match.get("versionStartIncluding")
                start_exc = match.get("versionStartExcluding")
                end_inc = match.get("versionEndIncluding")
                end_exc = match.get("versionEndExcluding")
                if start_inc or start_exc or end_inc or end_exc:
                    if _version_in_range(version, start_inc, start_exc, end_inc, end_exc):
                        return True
                    continue

                # No range given: the CPE's own version component may pin
                # an exact version (5th field of cpe:2.3:a:vendor:product:VERSION:...).
                if len(parts) > 5 and parts[5] not in ("*", "-") and parts[5] == version:
                    return True
    return False


@register_module
class CveCorrelationModule(ReconModule):
    name = "cve_correlation"
    run_order = 90

    def run(self, target: str, context: dict) -> list[Finding]:
        technologies = context.get("technologies", [])
        rate_limit = context.get("rate_limit", DEFAULT_RATE_LIMIT)
        general_min_interval = 1.0 / rate_limit
        nvd_delay = (
            AUTHENTICATED_DELAY_SECONDS if settings.nvd_api_key else UNAUTHENTICATED_DELAY_SECONDS
        )
        breaker = CircuitBreaker(
            context.get("circuit_breaker_threshold", DEFAULT_CIRCUIT_BREAKER_THRESHOLD)
        )
        audit = context.get("audit")
        findings: list[Finding] = []

        for index, tech in enumerate(technologies):
            name = tech.get("name")
            version = tech.get("version")
            host = tech.get("host", "")
            if not name or not version:
                continue

            tech_findings, succeeded = self._query_cves(name, version, host, audit)
            findings.extend(tech_findings)
            # The NVD-specific delay protects the shared NVD API; the
            # general rate limit also applies on top of it, so we sleep
            # whichever is stricter.
            time.sleep(max(nvd_delay, general_min_interval))

            if succeeded:
                breaker.record_success()
            elif breaker.record_failure():
                findings.append(
                    Finding(
                        type="circuit_breaker_tripped",
                        value=target,
                        data={
                            "module": self.name,
                            "skipped_technologies": len(technologies) - index - 1,
                        },
                    )
                )
                break

        return findings

    def _query_cves(
        self, name: str, version: str, host: str, audit: AuditLog | None
    ) -> tuple[list[Finding], bool]:
        # keywordSearch does a literal free-text match: searching "{name}
        # {version}" together returns almost nothing, since most CVE
        # descriptions don't quote the exact version. Search by name only,
        # then filter matches by the CPE version range NVD attaches to
        # each CVE -- that's the structured signal, not the prose.
        headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
        try:
            response = requests.get(
                NVD_API_URL,
                params={"keywordSearch": name},
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as exc:
            if audit is not None:
                audit.record(module=self.name, target=name, outcome=f"error: {exc}", url=NVD_API_URL)
            return [], False

        if audit is not None:
            audit.record(module=self.name, target=name, outcome=str(response.status_code), url=NVD_API_URL)

        findings = []
        for vulnerability in payload.get("vulnerabilities", []):
            cve = vulnerability.get("cve", {})
            if _cve_matches_version(cve, name, version):
                findings.append(self._finding_from_cve(cve, name, version, host, audit))
        return findings, True

    def _finding_from_cve(
        self, cve: dict, tech_name: str, tech_version: str, host: str, audit: AuditLog | None
    ) -> Finding:
        description_en = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )
        description_pt = (
            translate_en_to_pt(
                description_en,
                audit=audit,
                module=self.name,
                audit_target=cve.get("id", ""),
            )
            if description_en
            else None
        )
        epss_score = fetch_epss(cve.get("id", ""), audit=audit)

        cvss_score = None
        severity = None
        metrics = cve.get("metrics", {})
        for key in CVSS_METRIC_KEYS:
            entries = metrics.get(key)
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity")
                break

        return Finding(
            type="cve",
            value=cve.get("id", ""),
            data={
                "cvss_score": cvss_score,
                "severity": severity,
                "epss_score": epss_score,
                "description_en": description_en,
                "description_pt": description_pt,
                "matched_technology": tech_name,
                "matched_technology_version": tech_version,
                "host": host,
                "status": "suspected",
            },
        )
