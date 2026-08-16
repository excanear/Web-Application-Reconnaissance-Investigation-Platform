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
        headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
        try:
            response = requests.get(
                NVD_API_URL,
                params={"keywordSearch": f"{name} {version}"},
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
