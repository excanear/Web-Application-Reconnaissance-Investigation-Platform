from unittest.mock import MagicMock, patch

import requests

from app import epss
from app.audit import AuditLog


def _mock_response(payload, status_code=200):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload
    response.raise_for_status = MagicMock()
    return response


def test_returns_the_epss_score_when_the_api_call_succeeds():
    payload = {"data": [{"cve": "CVE-2021-44228", "epss": "0.94432940", "percentile": "0.99947"}]}

    with patch("app.epss.requests.get", return_value=_mock_response(payload)) as mock_get:
        result = epss.fetch_epss("CVE-2021-44228")

    assert result == 0.94432940
    assert mock_get.call_args.kwargs["params"] == {"cveId": "CVE-2021-44228"}


def test_returns_none_when_the_cve_is_absent_from_epss_data():
    payload = {"data": []}

    with patch("app.epss.requests.get", return_value=_mock_response(payload)):
        result = epss.fetch_epss("CVE-0000-00000")

    assert result is None


def test_returns_none_and_never_raises_when_the_api_call_fails():
    with patch("app.epss.requests.get", side_effect=requests.RequestException("epss is down")):
        result = epss.fetch_epss("CVE-2021-44228")

    assert result is None


def test_returns_none_for_a_malformed_score_without_raising():
    payload = {"data": [{"cve": "CVE-2021-44228", "epss": "not-a-number"}]}

    with patch("app.epss.requests.get", return_value=_mock_response(payload)):
        result = epss.fetch_epss("CVE-2021-44228")

    assert result is None


def test_returns_none_for_an_empty_cve_id_without_calling_the_api():
    with patch("app.epss.requests.get") as mock_get:
        result = epss.fetch_epss("")

    mock_get.assert_not_called()
    assert result is None


def test_records_a_successful_call_to_the_audit_log():
    payload = {"data": [{"cve": "CVE-2021-44228", "epss": "0.94432940"}]}
    audit = AuditLog()

    with patch("app.epss.requests.get", return_value=_mock_response(payload)):
        epss.fetch_epss("CVE-2021-44228", audit=audit)

    assert len(audit.entries) == 1
    assert audit.entries[0]["module"] == "cve_correlation"
    assert audit.entries[0]["target"] == "CVE-2021-44228"
    assert audit.entries[0]["outcome"] == "200"
    assert audit.entries[0]["url"] == epss.EPSS_API_URL


def test_records_a_failed_call_to_the_audit_log():
    audit = AuditLog()

    with patch("app.epss.requests.get", side_effect=requests.RequestException("epss is down")):
        epss.fetch_epss("CVE-2021-44228", audit=audit)

    assert len(audit.entries) == 1
    assert audit.entries[0]["outcome"] == "error: epss is down"
