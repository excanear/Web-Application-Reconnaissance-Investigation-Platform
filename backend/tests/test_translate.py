from unittest.mock import MagicMock, patch

import requests

from app import translate
from app.audit import AuditLog


def _mock_response(payload, status_code=200):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload
    response.raise_for_status = MagicMock()
    return response


def test_returns_none_without_calling_the_api_when_no_key_is_configured(monkeypatch):
    monkeypatch.setattr(translate.settings, "deepl_api_key", None)

    with patch("app.translate.requests.post") as mock_post:
        result = translate.translate_en_to_pt("A vuln.")

    mock_post.assert_not_called()
    assert result is None


def test_returns_translated_text_when_the_api_call_succeeds(monkeypatch):
    monkeypatch.setattr(translate.settings, "deepl_api_key", "test-key")
    payload = {"translations": [{"text": "Uma vulnerabilidade."}]}

    with patch("app.translate.requests.post", return_value=_mock_response(payload)) as mock_post:
        result = translate.translate_en_to_pt("A vuln.")

    assert result == "Uma vulnerabilidade."
    assert mock_post.call_args.kwargs["data"]["text"] == "A vuln."
    assert mock_post.call_args.kwargs["headers"]["Authorization"] == "DeepL-Auth-Key test-key"


def test_returns_none_and_never_raises_when_the_api_call_fails(monkeypatch):
    monkeypatch.setattr(translate.settings, "deepl_api_key", "test-key")

    with patch(
        "app.translate.requests.post",
        side_effect=requests.RequestException("deepl is down"),
    ):
        result = translate.translate_en_to_pt("A vuln.")

    assert result is None


def test_returns_none_for_empty_text_without_calling_the_api(monkeypatch):
    monkeypatch.setattr(translate.settings, "deepl_api_key", "test-key")

    with patch("app.translate.requests.post") as mock_post:
        result = translate.translate_en_to_pt("")

    mock_post.assert_not_called()
    assert result is None


def test_records_a_successful_call_to_the_audit_log(monkeypatch):
    monkeypatch.setattr(translate.settings, "deepl_api_key", "test-key")
    payload = {"translations": [{"text": "Uma vulnerabilidade."}]}
    audit = AuditLog()

    with patch("app.translate.requests.post", return_value=_mock_response(payload)):
        translate.translate_en_to_pt(
            "A vuln.", audit=audit, module="cve_correlation", audit_target="CVE-2021-23017"
        )

    assert len(audit.entries) == 1
    assert audit.entries[0]["module"] == "cve_correlation"
    assert audit.entries[0]["target"] == "CVE-2021-23017"
    assert audit.entries[0]["outcome"] == "200"
    assert audit.entries[0]["url"] == translate.DEEPL_API_URL


def test_records_a_failed_call_to_the_audit_log(monkeypatch):
    monkeypatch.setattr(translate.settings, "deepl_api_key", "test-key")
    audit = AuditLog()

    with patch(
        "app.translate.requests.post",
        side_effect=requests.RequestException("deepl is down"),
    ):
        translate.translate_en_to_pt("A vuln.", audit=audit, audit_target="CVE-2021-23017")

    assert len(audit.entries) == 1
    assert audit.entries[0]["outcome"] == "error: deepl is down"
