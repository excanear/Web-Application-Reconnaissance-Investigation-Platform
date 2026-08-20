import requests

from app.audit import AuditLog

EPSS_API_URL = "https://api.first.org/data/v1/epss"
REQUEST_TIMEOUT = 15


def fetch_epss(cve_id: str, audit: AuditLog | None = None) -> float | None:
    """Fetches a CVE's EPSS score (probability of exploitation, 0-1) from
    the FIRST.org public API -- free, no API key. Never raises: an empty
    CVE ID, any request failure, a CVE absent from EPSS's dataset, or a
    malformed score all return None -- a missing EPSS score must never
    fail a scan."""
    if not cve_id:
        return None

    try:
        response = requests.get(
            EPSS_API_URL,
            params={"cveId": cve_id},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        if audit is not None:
            audit.record(module="cve_correlation", target=cve_id, outcome=f"error: {exc}", url=EPSS_API_URL)
        return None

    if audit is not None:
        audit.record(module="cve_correlation", target=cve_id, outcome=str(response.status_code), url=EPSS_API_URL)

    data = payload.get("data", [])
    if not data:
        return None
    try:
        return float(data[0].get("epss"))
    except (TypeError, ValueError):
        return None
