import time

import requests

from app.config import settings
from app.modules.base import Finding, ReconModule, register_module

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 30

# NVD rate limits: 5 req/30s unauthenticated, 50 req/30s with an API key.
UNAUTHENTICATED_DELAY_SECONDS = 6.0
AUTHENTICATED_DELAY_SECONDS = 0.6

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


def _cve_matches_version(cve: dict, name: str, version: str) -> bool:
    needle = name.lower().replace(" ", "").replace("-", "").replace("_", "")
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                criteria = match.get("criteria", "").lower().replace("-", "").replace("_", "")
                if needle not in criteria:
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
                parts = match.get("criteria", "").split(":")
                if len(parts) > 5 and parts[5] not in ("*", "-") and parts[5] == version:
                    return True
    return False


@register_module
class CveCorrelationModule(ReconModule):
    name = "cve_correlation"
    run_order = 90

    def run(self, target: str, context: dict) -> list[Finding]:
        technologies = context.get("technologies", [])
        findings: list[Finding] = []

        for tech in technologies:
            name = tech.get("name")
            version = tech.get("version")
            if not name or not version:
                continue

            findings.extend(self._query_cves(name, version))
            time.sleep(
                AUTHENTICATED_DELAY_SECONDS if settings.nvd_api_key else UNAUTHENTICATED_DELAY_SECONDS
            )

        return findings

    def _query_cves(self, name: str, version: str) -> list[Finding]:
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
        except requests.RequestException:
            return []

        findings = []
        for vulnerability in payload.get("vulnerabilities", []):
            cve = vulnerability.get("cve", {})
            if _cve_matches_version(cve, name, version):
                findings.append(self._finding_from_cve(cve, name, version))
        return findings

    @staticmethod
    def _finding_from_cve(cve: dict, tech_name: str, tech_version: str) -> Finding:
        description = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )

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
                "description": description,
                "matched_technology": tech_name,
                "matched_technology_version": tech_version,
            },
        )
