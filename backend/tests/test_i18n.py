from app import i18n


def teardown_function(_fn):
    # Every test flips global CLI language state; reset to the default so
    # tests don't leak into each other.
    i18n.set_lang("en")


def test_t_returns_english_by_default():
    assert i18n.t("error_prefix") == "Error:"


def test_set_lang_switches_active_language():
    i18n.set_lang("pt")

    assert i18n.t("error_prefix") == "Erro:"


def test_t_falls_back_to_english_for_unknown_language():
    i18n.set_lang("fr")

    assert i18n.t("error_prefix") == "Error:"


def test_t_formats_placeholders():
    i18n.set_lang("en")

    assert i18n.t("scan_not_found", scan_id=42) == "Scan 42 not found."


def test_t_formats_placeholders_in_portuguese():
    i18n.set_lang("pt")

    assert i18n.t("scan_not_found", scan_id=42) == "Scan 42 nao encontrado."


def test_set_lang_rejects_unknown_language_key_lookup_but_keeps_going():
    # set_lang itself never raises - unknown languages are handled at
    # lookup time in t(), not by validating the language name up front.
    i18n.set_lang("klingon")

    assert i18n.t("error_prefix") == "Error:"
