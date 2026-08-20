import requests

from app.audit import AuditLog
from app.config import settings

DEEPL_API_URL = "https://api-free.deepl.com/v2/translate"
REQUEST_TIMEOUT = 15


def translate_en_to_pt(
    text: str,
    audit: AuditLog | None = None,
    module: str = "translate",
    audit_target: str | None = None,
) -> str | None:
    """Translates English text to Portuguese via the DeepL free API.
    Never raises: no configured key, empty input, or any request failure
    all return None -- a translation failure must never fail a scan."""
    if not settings.deepl_api_key or not text:
        return None

    target_label = audit_target or text[:50]
    try:
        response = requests.post(
            DEEPL_API_URL,
            data={"text": text, "source_lang": "EN", "target_lang": "PT-BR"},
            headers={"Authorization": f"DeepL-Auth-Key {settings.deepl_api_key}"},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        if audit is not None:
            audit.record(module=module, target=target_label, outcome=f"error: {exc}", url=DEEPL_API_URL)
        return None

    if audit is not None:
        audit.record(module=module, target=target_label, outcome=str(response.status_code), url=DEEPL_API_URL)

    translations = payload.get("translations", [])
    if not translations:
        return None
    return translations[0].get("text")
